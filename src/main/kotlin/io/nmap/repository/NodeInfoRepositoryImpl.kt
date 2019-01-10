package io.nmap.repository

import io.nmap.annotation.MapBacked
import net.corda.core.crypto.SecureHash
import net.corda.core.serialization.serialize
import net.corda.nodeapi.internal.SignedNodeInfo
import org.springframework.stereotype.Repository
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentMap

@Repository
@MapBacked
class NodeInfoRepositoryImpl : NodeInfoRepository {


    private val map: ConcurrentMap<SecureHash, Pair<SignedNodeInfo, ByteArray>> = ConcurrentHashMap()

    override fun persistSignedNodeInfo(signedNodeInfo: SignedNodeInfo) {
        map[signedNodeInfo.raw.hash] = signedNodeInfo to signedNodeInfo.serialize().bytes
    }

    override fun getSignedNodeInfo(hash: String): Pair<SignedNodeInfo, ByteArray>? = map[SecureHash.parse(hash)]


    override fun getAllHashes(): Collection<SecureHash> = map.keys.toSet()

    override fun purgeAllPersistedSignedNodeInfos(): Int = map.size.also { map.clear() }

}