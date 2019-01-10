package io.nmap


import net.corda.core.serialization.SerializationContext
import net.corda.core.serialization.internal.SerializationEnvironment
import net.corda.core.serialization.internal.SerializationEnvironmentImpl
import net.corda.core.serialization.internal.nodeSerializationEnv
import net.corda.core.utilities.ByteSequence

import net.corda.nodeapi.internal.serialization.AMQP_P2P_CONTEXT
import net.corda.nodeapi.internal.serialization.SerializationFactoryImpl
import net.corda.nodeapi.internal.serialization.amqp.AbstractAMQPSerializationScheme
import net.corda.nodeapi.internal.serialization.amqp.SerializerFactory

import org.springframework.stereotype.Component

@Component
class SerializationEngine {
    init {
        if (nodeSerializationEnv == null) {
            val classloader = this.javaClass.classLoader
            nodeSerializationEnv = SerializationEnvironmentImpl(
                    SerializationFactoryImpl().apply {
                        registerScheme(object : AbstractAMQPSerializationScheme(emptyList()) {
                            override fun canDeserializeVersion(byteSequence: ByteSequence, target: SerializationContext.UseCase): Boolean {
                                return (canDeserializeVersion(byteSequence) &&
                                        (target == SerializationContext.UseCase.P2P || target == SerializationContext.UseCase.Storage))
                            }
                            /*override fun canDeserializeVersion(magic: CordaSerializationMagic, target: SerializationContext.UseCase): Boolean {
                                return (magic == amqpMagic && target == SerializationContext.UseCase.P2P)
                            }*/

                            override fun rpcClientSerializerFactory(context: SerializationContext): SerializerFactory {
                                throw UnsupportedOperationException()
                            }

                            override fun rpcServerSerializerFactory(context: SerializationContext): SerializerFactory {
                                throw UnsupportedOperationException()
                            }
                        })
                    }, AMQP_P2P_CONTEXT.withClassLoader(classloader)
            )
        }
    }
}
