package io.nmap.service.certificate

import io.nmap.constants.AppConstants
import net.corda.core.internal.exists
import net.corda.nodeapi.internal.crypto.*
import org.springframework.stereotype.Service
import java.io.*
import java.nio.file.Path
import java.security.*
import java.security.cert.X509Certificate
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import javax.security.auth.x500.X500Principal
import java.io.ObjectOutputStream


@Service
class CertificateService{

    var keyPairMap : MutableMap<String, KeyPair>
    lateinit var rootCertificate: X509Certificate
    lateinit var intermediateCA: X509Certificate
    lateinit var networkCA: X509Certificate
    lateinit var nodeCA: X509Certificate
    private val path = AppConstants.HOME_PATH

    init {

        //LoadAll KeyPairs into map
        val keyPairPathList = listOf<Path>(path.resolve(AppConstants.ROOT+AppConstants.KEYPAIR_LITERAL),
                path.resolve(AppConstants.NETWORK + AppConstants.KEYPAIR_LITERAL),
                path.resolve(AppConstants.INTERMEDIATE + AppConstants.KEYPAIR_LITERAL),
                path.resolve(AppConstants.NODE_CA + AppConstants.KEYPAIR_LITERAL))
        keyPairMap = mutableMapOf()
        keyPairPathList.forEach {
            var keyPair: KeyPair?
            if(it.exists()){
                keyPair = deserializeKeyPair(it)
1            }else{
                keyPair = buildAndSerializeKeyPair(it)
            }
            keyPairMap[it.fileName.toString()] = keyPair
        }

        //Load Certificate
        val rootCertPath = path.resolve(AppConstants.ROOT+AppConstants.CERTIFICATE_LITERAL)
        val intermediateCertPath = path.resolve(AppConstants.INTERMEDIATE+ AppConstants.CERTIFICATE_LITERAL)
        val networkMapCertPath = path.resolve(AppConstants.NETWORK+ AppConstants.CERTIFICATE_LITERAL)
        val nodeCACertPath = path.resolve(AppConstants.NODE_CA + AppConstants.CERTIFICATE_LITERAL)

        if(rootCertPath.exists()){
            rootCertificate = X509Utilities.loadCertificateFromPEMFile(rootCertPath)
        }else{
            buildSelfSignedRootCertificate(keyPairMap[AppConstants.ROOT+ AppConstants.KEYPAIR_LITERAL]!!)
            X509Utilities.saveCertificateAsPEMFile(rootCertificate, rootCertPath)
        }

        if(intermediateCertPath.exists()){
            intermediateCA = X509Utilities.loadCertificateFromPEMFile(intermediateCertPath)
        }else{
            buildIntermediateCertificate(keyPairMap[AppConstants.INTERMEDIATE+ AppConstants.KEYPAIR_LITERAL]!!)
            X509Utilities.saveCertificateAsPEMFile(intermediateCA, intermediateCertPath)
        }

        if(networkMapCertPath.exists()){
            networkCA = X509Utilities.loadCertificateFromPEMFile(networkMapCertPath)
        }else{
            buildNetworkMapCertificate(keyPairMap[AppConstants.NETWORK + AppConstants.KEYPAIR_LITERAL]!!)
            X509Utilities.saveCertificateAsPEMFile(networkCA, networkMapCertPath)
        }

        if(nodeCACertPath.exists()){
            nodeCA = X509Utilities.loadCertificateFromPEMFile(nodeCACertPath)
        }else{
            buildNodeCACertificate(keyPairMap[AppConstants.NODE_CA + AppConstants.KEYPAIR_LITERAL]!!)
            X509Utilities.saveCertificateAsPEMFile(nodeCA, nodeCACertPath)
        }

    }

    private fun deserializeKeyPair(path: Path): KeyPair{
        /*val byteLength = path.toFile().length()
        val keyBytes = ByteArray(byteLength.toInt())
        val byteStream = ByteArrayInputStream(keyBytes)
        val objectStream = ObjectInputStream(byteStream)
        rootKeyPair = objectStream.readObject() as KeyPair
        objectStream.close()
        byteStream.close()*/
        val fileInputStream = FileInputStream(path.toFile())
        val objectStream = ObjectInputStream(fileInputStream)
        val keyPair = objectStream.readObject() as KeyPair
        objectStream.close()
        fileInputStream.close()
        return keyPair
    }

    private fun generateRSAKeyPair(): KeyPair{
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
        keyPairGenerator.initialize(4096)
        return keyPairGenerator.genKeyPair()
    }

    private fun buildAndSerializeKeyPair(path: Path): KeyPair{
        val keyPair = generateRSAKeyPair()
        val fileOutputStream = FileOutputStream(path.toFile())
        //val byteArrayStream = ByteArrayOutputStream()
        //val objectStream = ObjectOutputStream(byteArrayStream)
        val objectStream = ObjectOutputStream(fileOutputStream)
        objectStream.writeObject(keyPair)
        objectStream.close();
        //byteArrayStream.close();
        fileOutputStream.close()
        return keyPair
    }

    private fun buildSelfSignedRootCertificate(keyPair: KeyPair){
        rootCertificate = X509Utilities.createSelfSignedCACertificate(X500Principal(AppConstants.ROOT_X500_NAME), keyPair)
    }

    private fun buildIntermediateCertificate(intermediateCAKeyPair: KeyPair){
        intermediateCA = X509Utilities.createCertificate(CertificateType.INTERMEDIATE_CA, rootCertificate,
                keyPairMap[AppConstants.ROOT + AppConstants.KEYPAIR_LITERAL]!!,
                X500Principal(AppConstants.INTERMEDIATE_X500_NAME), intermediateCAKeyPair.public)
    }

    private fun buildNetworkMapCertificate(networkCAKeyPair: KeyPair){
        networkCA = X509Utilities.createCertificate(CertificateType.NETWORK_MAP, rootCertificate,
                keyPairMap[AppConstants.ROOT + AppConstants.KEYPAIR_LITERAL]!!,
                X500Principal(AppConstants.NETWORK_X500_NAME), networkCAKeyPair.public)
    }

    private fun buildNodeCACertificate(nodeCAKeyPair: KeyPair){
        nodeCA = X509Utilities.createCertificate(CertificateType.NODE_CA, intermediateCA,
                keyPairMap[AppConstants.INTERMEDIATE + AppConstants.KEYPAIR_LITERAL]!!,
                X500Principal(AppConstants.NODE_CA_X500_NAME), nodeCAKeyPair.public)
    }

    fun deserializeJksStore(path: Path, keyPair: KeyPair): KeyStore{
        TODO()
    }

    fun serializeKeyStore(path: Path, keyPair: KeyPair): KeyStore{
        TODO()
    }


    fun buildNodeCertificateStores(PARTY_A_X500: X500Principal){

        val tlsKeyStorePath = path.resolve(AppConstants.TLS_KEYSTORE_NAME)
        val trustStorePath = path.resolve(AppConstants.TRUST_STORE_NAME)
        val nodeStorePath = path.resolve(AppConstants.NODE_STORE_NAME)

        //Node SSL/TLS CA
        val clientTLSKeyPair = generateRSAKeyPair()
        val clientTLSCertificate = X509Utilities.createCertificate(CertificateType.TLS, nodeCA, clientTLSKeyPair,
                PARTY_A_X500, clientTLSKeyPair.public)

        val tlsKeyStore = loadOrCreateKeyStore(tlsKeyStorePath, "password")
        tlsKeyStore.addOrReplaceKey(X509Utilities.CORDA_CLIENT_TLS, clientTLSKeyPair.private, "password".toCharArray(),
                arrayOf(clientTLSCertificate, nodeCA, intermediateCA, rootCertificate))

        //Node truststore
        val trustStore = loadOrCreateKeyStore(trustStorePath, "password")
        trustStore.addOrReplaceCertificate(X509Utilities.CORDA_ROOT_CA, rootCertificate)
        trustStore.addOrReplaceCertificate(X509Utilities.CORDA_INTERMEDIATE_CA, intermediateCA)

        tlsKeyStore.save(tlsKeyStorePath, "password")
        trustStore.save(trustStorePath, "password")


        //Node Identity
        val nodeStore = loadOrCreateKeyStore(nodeStorePath, "password")
        val clientIdentityKeyPair = generateRSAKeyPair()
        val clientIdentityCert = X509Utilities.createCertificate(CertificateType.LEGAL_IDENTITY, nodeCA, clientIdentityKeyPair,
                PARTY_A_X500, clientIdentityKeyPair.public)
        val nodeIdentity = CertificateAndKeyPair(clientIdentityCert, clientIdentityKeyPair)
        nodeStore.addOrReplaceKey(X509Utilities.CORDA_CLIENT_CA,clientIdentityKeyPair.private, "password".toCharArray(),
                arrayOf(clientIdentityCert, nodeCA, intermediateCA,  rootCertificate ))
        nodeStore.addOrReplaceKey("identity-private-key", clientIdentityKeyPair.private, "password".toCharArray(),
                arrayOf(clientIdentityCert, nodeCA, intermediateCA,  rootCertificate ))

        nodeStore.save(nodeStorePath, "password")


        /*val clientIdentityKeyPair = generateRSAKeyPair()
        val clientidentityCert = X509Utilities.createCertificate(CertificateType.LEGAL_IDENTITY, nodeCA, clientIdentityKeyPair,
                PARTY_A_X500, clientIdentityKeyPair.public)

        val nodeIdentity = CertificateAndKeyPair(clientidentityCert, clientIdentityKeyPair)

        val certificatePath = listOf(nodeCA, intermediateCA, rootCertificate)

        val stream = FileOutputStream(File("$path/nodekeystore.jks"))
        val byteStream = ByteArrayOutputStream().use {
            ZipOutputStream(it).use { writeNodeKeyStore(it, nodeIdentity, certificatePath) }
            it
        }
        byteStream.writeTo(stream)
        byteStream.close()
        stream.close()*/

    }
/*
    private fun writeNodeKeyStore(it: ZipOutputStream, nodeIdentity: CertificateAndKeyPair, certificatePath: List<X509Certificate>) {
        it.putNextEntry(ZipEntry("nodekeystore.jks"))
        nodeIdentity.toKeyStore(X509Utilities.CORDA_CLIENT_CA, "identity-private-key",
                "password", certificatePath).store(it, "password".toCharArray())
        it.closeEntry()
    }

    fun CertificateAndKeyPair.toKeyStore(certAlias: String, keyAlias: String, password: String, certPath: List<X509Certificate> = listOf()): KeyStore {
        val passwordCharArray = password.toCharArray()
        val ks = KeyStore.getInstance("JKS")
        ks.load(null, null)
        ks.setCertificateEntry(certAlias, certificate)
        val certificates = listOf(certificate) + certPath
        ks.setKeyEntry(certAlias, keyPair.private, passwordCharArray, certificates.toTypedArray())
        ks.setKeyEntry(keyAlias, keyPair.private, passwordCharArray, certificates.toTypedArray())
        return ks
    }
*/
}

