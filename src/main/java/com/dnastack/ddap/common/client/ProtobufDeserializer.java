package com.dnastack.ddap.common.client;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Message;
import com.google.protobuf.util.JsonFormat;
import reactor.core.publisher.Mono;

public class ProtobufDeserializer {

    public static <T extends Message> Mono<T> fromJsonToMono(String json, T defaultMessageInstance) {
        try {
            return Mono.just(fromJson(json, defaultMessageInstance));
        } catch (InvalidProtocolBufferException e) {
            return Mono.error(e);
        }
    }

    public static <T extends Message> T fromJson(String json, T defaultMessageInstance) throws InvalidProtocolBufferException {
        Message.Builder builder = defaultMessageInstance.newBuilderForType();
        JsonFormat.parser()
                  .ignoringUnknownFields()
                  .merge(json, builder);
        return (T) builder.build();
    }

}
