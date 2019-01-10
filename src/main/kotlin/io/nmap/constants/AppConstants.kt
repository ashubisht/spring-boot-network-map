package io.nmap.constants

import org.apache.commons.io.FileUtils
import java.nio.file.Path
import java.nio.file.Paths

class AppConstants{
    companion object {
        const val PARTY_NAME_PREFIX = "CN="
        const val PARTY_NAME_SUFFIX = ",O=NmapSrv.io,L=Chandigarh,C=IN"
        const val ROOT_X500_NAME = "CN=Root_CA_1,O=NmapSrv.io,L=Chandigarh,C=IN"
        const val INTERMEDIATE_X500_NAME = "CN=Intermediate_CA_1,O=NmapSrv.io,L=Chandigarh,C=IN"
        const val NODE_CA_X500_NAME = "CN=NODE_CA_1,O=NmapSrv.io,L=Chandigarh,C=IN"
        const val NETWORK_X500_NAME = "CN=NETWORK_MAP_1,O=NmapSrv.io,L=Chandigarh,C=IN"

        val HOME_PATH: Path = Paths.get(FileUtils.getUserDirectory().path)

        const val ROOT = "rootCA"
        const val NETWORK = "networkMap"
        const val INTERMEDIATE = "intermediateCA"
        const val NODE_CA = "nodeCA"
        const val KEYPAIR_LITERAL = "KeyPair"
        const val CERTIFICATE_LITERAL = "Certificate"

        const val TLS_KEYSTORE_NAME = "sslkeystore.jks"
        const val NODE_STORE_NAME = "nodekeystore.jks"
        const val TRUST_STORE_NAME = "truststore.jks"

    }
}