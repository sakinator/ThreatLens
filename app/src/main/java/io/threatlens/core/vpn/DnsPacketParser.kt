package io.threatlens.core.vpn

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

object DnsPacketParser {

    data class ParsedDnsQuery(
        val transactionId: Short,
        val domain: String,
        val qType: Int,
        val qClass: Int,
        val questionBytes: ByteArray,
        val rawDnsPayload: ByteArray,
        val srcPort: Int,
        val dstPort: Int,
        val srcIp: ByteArray,
        val dstIp: ByteArray
    )

    fun parseQuery(packet: ByteArray, length: Int): ParsedDnsQuery? {
        try {
            if (length < 28) return null // 20 IP + 8 UDP min
            val versionAndIhl = packet[0].toInt() and 0xFF
            val version = versionAndIhl ushr 4
            if (version != 4) return null // Only IPv4 for DNS loopback TUN
            val ihl = (versionAndIhl and 0x0F) * 4
            if (length < ihl + 8 + 12) return null

            val protocol = packet[9].toInt() and 0xFF
            if (protocol != 17) return null // Not UDP

            val srcIp = packet.copyOfRange(12, 16)
            val dstIp = packet.copyOfRange(16, 20)

            val srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
            val dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)

            if (dstPort != 53) return null // Not DNS query

            val udpPayloadOffset = ihl + 8
            val udpPayloadLength = length - udpPayloadOffset
            if (udpPayloadLength < 12) return null

            val dnsPayload = packet.copyOfRange(udpPayloadOffset, length)
            val buffer = ByteBuffer.wrap(dnsPayload)

            val id = buffer.short
            val flags = buffer.short.toInt() and 0xFFFF
            val isQuery = (flags and 0x8000) == 0
            if (!isQuery) return null

            val qdCount = buffer.short.toInt() and 0xFFFF
            if (qdCount < 1) return null
            buffer.short // ancount
            buffer.short // nscount
            buffer.short // arcount

            val questionStartOffset = buffer.position()

            // Parse QNAME
            val domainBuilder = StringBuilder()
            var labelLen = buffer.get().toInt() and 0xFF
            while (labelLen > 0) {
                if (buffer.remaining() < labelLen) return null
                val labelBytes = ByteArray(labelLen)
                buffer.get(labelBytes)
                if (domainBuilder.isNotEmpty()) domainBuilder.append('.')
                domainBuilder.append(String(labelBytes, Charsets.US_ASCII))
                labelLen = buffer.get().toInt() and 0xFF
            }

            val qType = buffer.short.toInt() and 0xFFFF
            val qClass = buffer.short.toInt() and 0xFFFF
            val questionEndOffset = buffer.position()

            val questionBytes = dnsPayload.copyOfRange(questionStartOffset, questionEndOffset)

            return ParsedDnsQuery(
                transactionId = id,
                domain = domainBuilder.toString(),
                qType = qType,
                qClass = qClass,
                questionBytes = questionBytes,
                rawDnsPayload = dnsPayload,
                srcPort = srcPort,
                dstPort = dstPort,
                srcIp = srcIp,
                dstIp = dstIp
            )
        } catch (_: Exception) {
            return null
        }
    }

    fun buildSinkholeResponsePacket(query: ParsedDnsQuery): ByteArray {
        val dnsOut = ByteArrayOutputStream()

        // 1. DNS Header (12 bytes)
        val idBytes = ByteBuffer.allocate(2).putShort(query.transactionId).array()
        dnsOut.write(idBytes)
        // Flags: 0x8180 (Response, Opcode=0, Authoritative=0, Recursion Desired=1, Recursion Available=1, Rcode=0 NoError)
        dnsOut.write(byteArrayOf(0x81.toByte(), 0x80.toByte()))
        // QDCOUNT = 1
        dnsOut.write(byteArrayOf(0x00, 0x01))
        // ANCOUNT = 1 (A record with 0.0.0.0)
        dnsOut.write(byteArrayOf(0x00, 0x01))
        // NSCOUNT = 0
        dnsOut.write(byteArrayOf(0x00, 0x00))
        // ARCOUNT = 0
        dnsOut.write(byteArrayOf(0x00, 0x00))

        // 2. Question section (replicated)
        dnsOut.write(query.questionBytes)

        // 3. Answer section
        // Compression pointer to Question Name (0xC00C -> offset 12)
        dnsOut.write(byteArrayOf(0xC0.toByte(), 0x0C))
        // Type: 0x0001 (A)
        dnsOut.write(byteArrayOf(0x00, 0x01))
        // Class: 0x0001 (IN)
        dnsOut.write(byteArrayOf(0x00, 0x01))
        // TTL: 300 seconds (0x0000012C)
        dnsOut.write(byteArrayOf(0x00, 0x00, 0x01, 0x2C))
        // Data length: 4 bytes
        dnsOut.write(byteArrayOf(0x00, 0x04))
        // IP: 0.0.0.0 (Sinkhole loopback drop)
        dnsOut.write(byteArrayOf(0x00, 0x00, 0x00, 0x00))

        val dnsResponsePayload = dnsOut.toByteArray()
        return wrapInIpUdpPacket(
            dnsPayload = dnsResponsePayload,
            srcIp = query.dstIp,
            dstIp = query.srcIp,
            srcPort = query.dstPort,
            dstPort = query.srcPort
        )
    }

    fun wrapInIpUdpPacket(
        dnsPayload: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLength = ipHeaderLen + udpHeaderLen + dnsPayload.size

        val packet = ByteArray(totalLength)
        val buffer = ByteBuffer.wrap(packet)

        // IPv4 Header
        buffer.put(0x45.toByte()) // Version 4, IHL 5 (20 bytes)
        buffer.put(0x00.toByte()) // DSCP/ECN
        buffer.putShort(totalLength.toShort()) // Total Length
        buffer.putShort(0x0000.toShort()) // Identification
        buffer.putShort(0x4000.toShort()) // Flags: Don't Fragment
        buffer.put(64.toByte()) // TTL
        buffer.put(17.toByte()) // Protocol: UDP (17)
        buffer.putShort(0x0000.toShort()) // Checksum placeholder
        buffer.put(srcIp)
        buffer.put(dstIp)

        // Calculate IPv4 Header Checksum
        val ipChecksum = computeIpChecksum(packet, 0, ipHeaderLen)
        packet[10] = (ipChecksum ushr 8).toByte()
        packet[11] = (ipChecksum and 0xFF).toByte()

        // UDP Header
        buffer.position(ipHeaderLen)
        buffer.putShort(srcPort.toShort())
        buffer.putShort(dstPort.toShort())
        buffer.putShort((udpHeaderLen + dnsPayload.size).toShort())
        buffer.putShort(0x0000.toShort()) // UDP Checksum (0 is valid in IPv4)

        // DNS Payload
        buffer.put(dnsPayload)

        return packet
    }

    private fun computeIpChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var i = offset
        while (i < offset + length) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }
        while ((sum ushr 16) > 0) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv() and 0xFFFF
    }
}
