package io.nmap.controller.networkcontroller

import io.nmap.SerializationEngine
import io.nmap.annotation.MapBacked
import io.nmap.constants.AppConstants
import io.nmap.repository.NodeInfoRepository
import io.nmap.service.certificate.CertificateService
import io.nmap.service.notary.NotaryInfoLoader
import net.corda.core.crypto.SecureHash
import net.corda.core.internal.SignedDataWithCert
import net.corda.core.internal.signWithCert
import net.corda.core.node.NetworkParameters
import net.corda.core.serialization.SerializedBytes
import net.corda.core.serialization.deserialize
import net.corda.core.serialization.serialize
import net.corda.nodeapi.internal.SignedNodeInfo
import net.corda.nodeapi.internal.network.NetworkMap
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.*
import java.time.Instant
import java.util.concurrent.ThreadLocalRandom
import java.util.concurrent.atomic.AtomicReference

@RestController
class NetworkService (@Autowired @MapBacked private val nodeInfoRepository: NodeInfoRepository,
                      @Autowired private val notaryInfoLoader: NotaryInfoLoader,
                      @Autowired private val certificateService: CertificateService,
                      @Suppress("unused") @Autowired private val serializationEngine: SerializationEngine
) {


    private val networkMap: AtomicReference<SerializedBytes<SignedDataWithCert<NetworkMap>>> = AtomicReference()
    private val signedNetworkParams: SignedDataWithCert<NetworkParameters>

    init {
        val networkParams = NetworkParameters(
                minimumPlatformVersion = 1,
                notaries = notaryInfoLoader.load(),
                maxMessageSize = Integer.MAX_VALUE,
                maxTransactionSize = Integer.MAX_VALUE,
                modifiedTime = Instant.now(),
                epoch = 10,
                whitelistedContractImplementations = emptyMap() //Type : <String, List<AttachmentId>>
        )
        signedNetworkParams = networkParams.signWithCert(
                certificateService.keyPairMap[AppConstants.NETWORK + AppConstants.KEYPAIR_LITERAL]!!.private,
                certificateService.networkCA)
        networkMap.set(buildNetworkMap())
    }

    @GetMapping(path = ["/ping"])
    fun ping(): ByteArray {
        return "OK".toByteArray()
    }

    @PostMapping(path = ["network-map/publish"])
    fun postNodeInfo(@RequestBody input: ByteArray): ResponseEntity<String> {
        val deserializedSignedNodeInfo = input.deserialize<SignedNodeInfo>()
        deserializedSignedNodeInfo.verified()
        nodeInfoRepository.persistSignedNodeInfo(deserializedSignedNodeInfo)
        networkMap.set(buildNetworkMap())

        return ResponseEntity.ok().body("OK")
    }


    private fun buildNetworkMap(): SerializedBytes<SignedDataWithCert<NetworkMap>> {
        val allNodes = nodeInfoRepository.getAllHashes()
        return NetworkMap(allNodes.toList(), signedNetworkParams.raw.hash, null).
                signWithCert(certificateService.keyPairMap[AppConstants.NETWORK + AppConstants.KEYPAIR_LITERAL]!!.private,
                        certificateService.networkCA).serialize()
    }


    @GetMapping(value = "/network-map")
    fun getNetworkMap(): ResponseEntity<ByteArray>{
       val serializedNetworkMap = networkMap.get()
        if(serializedNetworkMap != null){
            return ResponseEntity.ok()
                    .contentLength(serializedNetworkMap.size.toLong())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header("Cache-Control",
                            "max-age=${ThreadLocalRandom.current().nextInt(10, 30)}")
                    .body(serializedNetworkMap.bytes)
        }else{
            return ResponseEntity(HttpStatus.NOT_FOUND)
        }
    }

    @GetMapping(path = ["network-map/network-parameters/{hash}"], produces = [MediaType.APPLICATION_OCTET_STREAM_VALUE])
    fun getNetworkParams(@PathVariable("hash") hash: String): ResponseEntity<ByteArray> {

        return if (SecureHash.parse(hash) == signedNetworkParams.raw.hash) {
            ResponseEntity.ok().
                    header("Cache-Control", "max-age=${ThreadLocalRandom.current().nextInt(10, 30)}")
                    .body(signedNetworkParams.serialize().bytes)
        } else {
            ResponseEntity.notFound().build<ByteArray>()
        }
    }

    @GetMapping(path = ["network-map/node-info/{hash}"])
    fun getNodeInfo(@PathVariable("hash") hash: String): ResponseEntity<ByteArray>? {
        val foundNodeInfo = nodeInfoRepository.getSignedNodeInfo(hash)
        return if (foundNodeInfo == null) {
            ResponseEntity.notFound().build()
        } else {
            return ResponseEntity.ok()
                    .contentLength(foundNodeInfo.second.size.toLong())
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .body(foundNodeInfo.second)
        }
    }

}