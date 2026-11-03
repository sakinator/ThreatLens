package io.threatlens.core.vpn

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * High-Speed On-Device TCP Sinkhole Responder for ThreatLens Web Shield.
 *
 * When a user or application requests an HTTP connection to a blocked domain or IP address,
 * this responder synthesizes a lightweight TCP handshake and serves a dark-cyber "Blocked by ThreatLens"
 * HTML landing page directly on the loopback TUN interface.
 *
 * For non-HTTP ports (such as HTTPS port 443 or background API ports), it drops the connection or sends
 * TCP RST immediately so malicious C2 traffic and trackers are blocked with 0ms latency.
 */
object SinkholeTcpResponder {

    const val SINKHOLE_IP = "10.111.222.1"
    val SINKHOLE_IP_BYTES = byteArrayOf(10, 111, 222.toByte(), 1)

    /**
     * Inspects incoming IP packets on the TUN interface.
     * If the packet is TCP destined for the sinkhole IP, processes the TCP handshake or HTTP payload.
     *
     * @return true if packet was handled by the TCP sinkhole responder.
     */
    fun handleTcpPacket(packet: ByteArray, length: Int, output: OutputStream): Boolean {
        try {
            if (length < 40) return false // 20 IP + 20 TCP min
            val versionAndIhl = packet[0].toInt() and 0xFF
            val version = versionAndIhl ushr 4
            if (version != 4) return false
            val ihl = (versionAndIhl and 0x0F) * 4
            if (length < ihl + 20) return false

            val protocol = packet[9].toInt() and 0xFF
            if (protocol != 6) return false // TCP only

            val srcIp = packet.copyOfRange(12, 16)
            val dstIp = packet.copyOfRange(16, 20)

            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)

            val clientSeq = readInt32(packet, ihl + 4)
            val clientAck = readInt32(packet, ihl + 8)

            val dataOffset = ((packet[ihl + 12].toInt() and 0xFF) ushr 4) * 4
            val flags = packet[ihl + 13].toInt() and 0xFF
            val tcpPayloadOffset = ihl + dataOffset
            val tcpPayloadLength = length - tcpPayloadOffset

            // Only respond to traffic directed at our sinkhole IP on HTTP Port 80
            // Non-HTTP traffic (port 443 or API ports) is dropped or reset so malicious traffic cannot escape
            if (dstPort != 80) {
                // If client tries to open connection to non-80 port (e.g. HTTPS or custom port), send TCP RST
                if ((flags and 0x02) != 0) { // SYN
                    val rstPacket = buildTcpPacket(
                        srcIp = dstIp,
                        dstIp = srcIp,
                        srcPort = dstPort,
                        dstPort = srcPort,
                        seq = clientAck,
                        ack = clientSeq + 1,
                        flags = 0x14, // RST | ACK
                        payload = ByteArray(0)
                    )
                    output.write(rstPacket)
                    return true
                }
                return false
            }

            // HTTP Port 80 Handling
            // 1. TCP SYN: Complete 3-Way Handshake
            if ((flags and 0x02) != 0) {
                val synAckPacket = buildTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seq = 1000000L,
                    ack = clientSeq + 1,
                    flags = 0x12, // SYN | ACK
                    payload = ByteArray(0)
                )
                output.write(synAckPacket)
                return true
            }

            // 2. HTTP Request (GET / POST)
            if (tcpPayloadLength > 0) {
                val requestPayload = String(packet, tcpPayloadOffset, tcpPayloadLength, StandardCharsets.US_ASCII)
                val lines = requestPayload.split("\r\n")
                val requestLine = lines.firstOrNull() ?: ""
                val hostHeader = lines.firstOrNull { it.startsWith("Host:", ignoreCase = true) }
                    ?.substringAfter(":")?.trim() ?: "blocked-threat.local"

                var requestedPath = "/"
                val parts = requestLine.split(" ")
                if (parts.size >= 2) {
                    requestedPath = parts[1]
                }

                // Handle interactive Unblock & Whitelist action directly from webpage!
                val httpResponse: ByteArray
                if (requestedPath.startsWith("/__threatlens_unblock")) {
                    val domainToUnblock = extractQueryParam(requestedPath, "domain") ?: hostHeader
                    DomainFilterEngine.whitelistDomain(domainToUnblock)
                    httpResponse = buildHttpSuccessResponse(domainToUnblock)
                } else {
                    // Standard Threat Block Page
                    val decision = DomainFilterEngine.evaluateDomain(hostHeader)
                    val htmlContent = generateBlockPageHtml(
                        domain = hostHeader,
                        category = decision.category.label,
                        reason = decision.reason
                    )
                    httpResponse = buildHttpResponse(htmlContent)
                }

                val responsePacket = buildTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seq = clientAck,
                    ack = clientSeq + tcpPayloadLength,
                    flags = 0x19, // PSH | ACK | FIN
                    payload = httpResponse
                )
                output.write(responsePacket)
                return true
            }

            // 3. Client FIN: Acknowledge connection termination
            if ((flags and 0x01) != 0) {
                val finAckPacket = buildTcpPacket(
                    srcIp = dstIp,
                    dstIp = srcIp,
                    srcPort = dstPort,
                    dstPort = srcPort,
                    seq = clientAck,
                    ack = clientSeq + 1,
                    flags = 0x10, // ACK
                    payload = ByteArray(0)
                )
                output.write(finAckPacket)
                return true
            }

            return false
        } catch (_: Exception) {
            return false
        }
    }

    fun generateBlockPageHtml(domain: String, category: String, reason: String): String {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Intercepted • ThreatLens</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: #050B14;
      color: #E6EDF3;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      padding: 20px;
    }
    .card {
      background: #0B1528;
      border: 1px solid #FF0055;
      box-shadow: 0 0 25px rgba(255, 0, 85, 0.25);
      border-radius: 16px;
      max-width: 520px;
      width: 100%;
      padding: 32px 24px;
      text-align: center;
    }
    .shield-icon {
      width: 64px;
      height: 64px;
      margin: 0 auto 16px;
      display: block;
    }
    h1 {
      font-size: 20px;
      font-weight: 900;
      letter-spacing: 1.5px;
      color: #FFFFFF;
      margin-bottom: 6px;
    }
    .subtitle {
      font-size: 13px;
      color: #00E5FF;
      font-weight: 700;
      letter-spacing: 0.5px;
      text-transform: uppercase;
      margin-bottom: 20px;
    }
    .badge-category {
      display: inline-block;
      background: rgba(255, 0, 85, 0.15);
      border: 1px solid #FF0055;
      color: #FF0055;
      font-size: 11px;
      font-weight: 800;
      padding: 4px 12px;
      border-radius: 20px;
      margin-bottom: 16px;
      letter-spacing: 0.5px;
    }
    .domain-box {
      background: #03070E;
      border: 1px solid #1E293B;
      border-radius: 8px;
      padding: 12px;
      font-family: 'Courier New', Courier, monospace;
      font-size: 14px;
      font-weight: 700;
      color: #FFFFFF;
      word-break: break-all;
      margin-bottom: 16px;
    }
    .reason-box {
      font-size: 13px;
      line-height: 1.5;
      color: #94A3B8;
      background: #0E1A33;
      border-radius: 8px;
      padding: 12px;
      margin-bottom: 24px;
      text-align: left;
    }
    .reason-box strong {
      color: #E2E8F0;
      display: block;
      margin-bottom: 4px;
    }
    .btn-unblock {
      display: block;
      width: 100%;
      background: #00E5FF;
      color: #050B14;
      text-decoration: none;
      font-weight: 900;
      font-size: 13px;
      padding: 14px;
      border-radius: 8px;
      letter-spacing: 0.5px;
      transition: background 0.2s ease;
      cursor: pointer;
    }
    .btn-unblock:hover {
      background: #33EBFF;
    }
    .footer {
      margin-top: 24px;
      font-size: 11px;
      color: #64748B;
      letter-spacing: 0.5px;
    }
    .footer span {
      color: #00E5FF;
      font-weight: 700;
    }
  </style>
</head>
<body>
  <div class="card">
    <svg class="shield-icon" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 6V11.5C3 17 6.8 21.8 12 23C17.2 21.8 21 17 21 11.5V6L12 2Z" fill="#FF0055" fill-opacity="0.2" stroke="#FF0055" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      <path d="M12 8V13M12 16H12.01" stroke="#FFFFFF" stroke-width="2" stroke-linecap="round"/>
    </svg>
    <h1>ACCESS BLOCKED</h1>
    <div class="subtitle">ThreatLens Autonomous Web Shield</div>
    <div class="badge-category">$category</div>
    <div class="domain-box">$domain</div>
    <div class="reason-box">
      <strong>Interception Rationale:</strong>
      $reason
    </div>
    <a href="/__threatlens_unblock?domain=$domain" class="btn-unblock">✓ Unblock & Whitelist Domain</a>
    <div class="footer">Protected by <span>ThreatLens v1.6.0</span> • Zero-Battery On-Device Loopback</div>
  </div>
</body>
</html>
        """.trimIndent()
    }

    private fun buildHttpSuccessResponse(domain: String): ByteArray {
        val html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Domain Whitelisted • ThreatLens</title>
  <style>
    body {
      background: #050B14;
      color: #E6EDF3;
      font-family: -apple-system, sans-serif;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      text-align: center;
      padding: 20px;
    }
    .card {
      background: #0B1528;
      border: 1px solid #00E676;
      border-radius: 16px;
      padding: 32px 24px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 0 25px rgba(0, 230, 118, 0.25);
    }
    h1 { color: #00E676; font-size: 20px; margin-bottom: 8px; }
    p { font-size: 13px; color: #94A3B8; margin-bottom: 20px; }
    .domain { font-family: monospace; font-size: 15px; color: #FFFFFF; background: #03070E; padding: 10px; border-radius: 6px; margin-bottom: 20px; }
    .btn { display: inline-block; background: #00E676; color: #050B14; text-decoration: none; font-weight: bold; padding: 12px 20px; border-radius: 6px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>✓ Domain Whitelisted</h1>
    <p>ThreatLens has added this address to your authorized whitelist. You can now access it freely.</p>
    <div class="domain">$domain</div>
    <a href="http://$domain" class="btn">Proceed to Website</a>
  </div>
</body>
</html>
        """.trimIndent()
        return buildHttpResponse(html)
    }

    private fun buildHttpResponse(html: String): ByteArray {
        val bytes = html.toByteArray(StandardCharsets.UTF_8)
        val header = "HTTP/1.1 200 OK\r\n" +
                "Content-Type: text/html; charset=UTF-8\r\n" +
                "Connection: close\r\n" +
                "Content-Length: ${bytes.size}\r\n\r\n"
        val headerBytes = header.toByteArray(StandardCharsets.US_ASCII)
        val out = ByteArrayOutputStream(headerBytes.size + bytes.size)
        out.write(headerBytes)
        out.write(bytes)
        return out.toByteArray()
    }

    private fun extractQueryParam(path: String, key: String): String? {
        val queryStart = path.indexOf('?')
        if (queryStart == -1) return null
        val query = path.substring(queryStart + 1)
        for (pair in query.split("&")) {
            val kv = pair.split("=")
            if (kv.size == 2 && kv[0] == key) {
                return java.net.URLDecoder.decode(kv[1], "UTF-8")
            }
        }
        return null
    }

    private fun readInt32(data: ByteArray, offset: Int): Long {
        return (((data[offset].toLong() and 0xFF) shl 24) or
                ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or
                (data[offset + 3].toLong() and 0xFF)) and 0xFFFFFFFFL
    }

    fun buildTcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val totalLength = ipHeaderLen + tcpHeaderLen + payload.size
        val packet = ByteArray(totalLength)

        // 1. IPv4 Header
        packet[0] = 0x45.toByte() // Version 4, IHL 5
        packet[1] = 0x00.toByte() // TOS
        packet[2] = ((totalLength ushr 8) and 0xFF).toByte()
        packet[3] = (totalLength and 0xFF).toByte()
        packet[4] = 0x12.toByte() // ID
        packet[5] = 0x34.toByte()
        packet[6] = 0x40.toByte() // Don't Fragment
        packet[7] = 0x00.toByte()
        packet[8] = 64.toByte()   // TTL
        packet[9] = 6.toByte()    // Protocol: TCP (6)
        packet[10] = 0.toByte()   // Checksum placeholder
        packet[11] = 0.toByte()
        System.arraycopy(srcIp, 0, packet, 12, 4)
        System.arraycopy(dstIp, 0, packet, 16, 4)

        val ipChecksum = computeChecksum(packet, 0, ipHeaderLen)
        packet[10] = ((ipChecksum ushr 8) and 0xFF).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // 2. TCP Header
        val tcpOffset = ipHeaderLen
        packet[tcpOffset] = ((srcPort ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 1] = (srcPort and 0xFF).toByte()
        packet[tcpOffset + 2] = ((dstPort ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 3] = (dstPort and 0xFF).toByte()

        // Sequence number (32-bit)
        packet[tcpOffset + 4] = ((seq ushr 24) and 0xFF).toByte()
        packet[tcpOffset + 5] = ((seq ushr 16) and 0xFF).toByte()
        packet[tcpOffset + 6] = ((seq ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 7] = (seq and 0xFF).toByte()

        // Acknowledgment number (32-bit)
        packet[tcpOffset + 8] = ((ack ushr 24) and 0xFF).toByte()
        packet[tcpOffset + 9] = ((ack ushr 16) and 0xFF).toByte()
        packet[tcpOffset + 10] = ((ack ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 11] = (ack and 0xFF).toByte()

        // Data offset (5 words = 20 bytes) & Flags
        packet[tcpOffset + 12] = 0x50.toByte()
        packet[tcpOffset + 13] = (flags and 0xFF).toByte()

        // Window size: 64240
        packet[tcpOffset + 14] = 0xFA.toByte()
        packet[tcpOffset + 15] = 0xF0.toByte()

        // Checksum placeholder
        packet[tcpOffset + 16] = 0.toByte()
        packet[tcpOffset + 17] = 0.toByte()

        // Urgent pointer: 0
        packet[tcpOffset + 18] = 0.toByte()
        packet[tcpOffset + 19] = 0.toByte()

        // Copy payload
        if (payload.isNotEmpty()) {
            System.arraycopy(payload, 0, packet, ipHeaderLen + tcpHeaderLen, payload.size)
        }

        // 3. Compute TCP Checksum using IPv4 Pseudo-Header
        val tcpLen = tcpHeaderLen + payload.size
        val pseudoHeader = ByteBuffer.allocate(12 + tcpLen)
        pseudoHeader.put(srcIp)
        pseudoHeader.put(dstIp)
        pseudoHeader.put(0.toByte())
        pseudoHeader.put(6.toByte()) // TCP
        pseudoHeader.putShort(tcpLen.toShort())
        pseudoHeader.put(packet, tcpOffset, tcpLen)

        val tcpChecksum = computeChecksum(pseudoHeader.array(), 0, pseudoHeader.position())
        packet[tcpOffset + 16] = ((tcpChecksum ushr 8) and 0xFF).toByte()
        packet[tcpOffset + 17] = (tcpChecksum and 0xFF).toByte()

        return packet
    }

    private fun computeChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        val end = offset + length
        while (i < end - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        if (i < end) {
            val word = (data[i].toInt() and 0xFF) shl 8
            sum += word
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}
