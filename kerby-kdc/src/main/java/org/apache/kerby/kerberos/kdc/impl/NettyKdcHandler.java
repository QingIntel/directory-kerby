/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.kerby.kerberos.kdc.impl;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.apache.kerby.kerberos.kerb.server.KdcContext;
import org.apache.kerby.kerberos.kerb.server.KdcHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetSocketAddress;
import java.nio.ByteBuffer;

public class NettyKdcHandler extends ChannelInboundHandlerAdapter {
    private final KdcHandler myKdcHandler;
    private static final Logger LOG = LoggerFactory.getLogger(NettyKdcHandler.class);



    /**
     *
    public static int REQ_COUNT = 0;
    public static int SUM_PROC_TIME = 1;
    public static int MIN_PROC_TIME = 2;
    public static int MAX_PROC_TIME = 3;
     private static long[] statData = new long[4];
     private static Object statDataLock = new Object();
     */

    /**
     *
     * @param reset
     * @return

    public static long[] getStatData(boolean reset) {
        long[] ret;
        synchronized (statDataLock) {
            ret = statData.clone();
            if (reset) {
                statData[0] = 0;
                statData[1] = 0;
                statData[2] = 0;
                statData[3] = 0;
            }
        }
        return ret;
    }
     */

    public NettyKdcHandler(KdcContext kdcContext) {
        this.myKdcHandler = new KdcHandler(kdcContext);
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx,
                            Object msg) throws Exception {
        ByteBuf byteBuf = (ByteBuf) msg;
        byte[] msgBytes = new byte[byteBuf.readableBytes()];
        byteBuf.readBytes(msgBytes);
        ByteBuffer requestMessage = ByteBuffer.wrap(msgBytes);
        byteBuf.release();

        InetSocketAddress clientAddress =
                (InetSocketAddress) ctx.channel().remoteAddress();
        boolean isTcp = true; //TODO:
        try {
            //long stm = System.nanoTime();
            ByteBuffer responseMessage = myKdcHandler.handleMessage(requestMessage,
                    isTcp, clientAddress.getAddress());
            ctx.writeAndFlush(Unpooled.wrappedBuffer(responseMessage));
            //long cost = System.nanoTime() - stm;
            /**
             *
            synchronized (statDataLock) {
                statData[0]++;
                statData[1] += cost;
                statData[2] = statData[2] > cost ? cost : statData[2] == 0 ? cost : statData[2];
                statData[3] = statData[2] > cost ? statData[2] : cost;
            }
             */
        } catch (Exception e) {
            LOG.error("Error occurred while processing request:"
                    + e);
        }
    }
}
