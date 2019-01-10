package io.nmap.service.notary

import io.nmap.SerializationEngine
import net.corda.core.identity.Party
import net.corda.core.internal.readObject
import net.corda.core.node.NodeInfo
import net.corda.core.node.NotaryInfo
import net.corda.nodeapi.internal.SignedNodeInfo
import org.apache.commons.io.FileUtils
import org.apache.commons.io.filefilter.DirectoryFileFilter
import org.apache.commons.io.filefilter.RegexFileFilter
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.ApplicationContext
import org.springframework.stereotype.Service

@Service
class NotaryInfoLoaderImpl (
        @Autowired val context : ApplicationContext,
        @Value("\${nodesDirectoryUrl:classpath:nodes}") private val nodesDirectoryUrl: String
        , @Suppress("unused") @Autowired private val serializationEngine: SerializationEngine
) : NotaryInfoLoader {

    private fun NodeInfo.notaryIdentity(): Party {
        return when (legalIdentities.size) {
            1 -> legalIdentities[0]
            else -> throw IllegalArgumentException("Not sure how to get the notary identity in this scenario: $this")
        }
    }

    override fun load(): List<NotaryInfo> {
        val directoryToLoadFrom = context.getResource(nodesDirectoryUrl).file
        val nodeInfoFiles = FileUtils.listFiles(
                directoryToLoadFrom,
                RegexFileFilter("nodeInfo-.*"),
                DirectoryFileFilter.DIRECTORY
        )
        nodeInfoFiles.forEach{
            println("NodeInfoFiles" + it.path)
        }
        return nodeInfoFiles.map {
            val nodeInfo = it.toPath().readObject<SignedNodeInfo>()
            NotaryInfo(nodeInfo.verified().notaryIdentity(), false)
        }
    }

}