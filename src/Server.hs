{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeApplications #-}

module Server (start) where

import Common.Config (ServerConfig (..))
import Common.Logger (debug_, error_, info_, loggers, trace_)
import Common.Protocol (Protocol (..))
import Control.Concurrent.Async (concurrently)
import Control.Monad (void)
import Server.Protocol (ServerProtocol (label, newServerContext))
import qualified Server.Protocol.Shadowsocks as Shadowsocks
import qualified Server.Protocol.Trojan as Trojan
import qualified Server.Protocol.VMess as VMess
import qualified Server.Transport.Shadowsocks.Datagram
import qualified Server.Transport.Stream

$(loggers "Server" ['debug_, 'info_, 'trace_, 'error_])

start :: ServerConfig -> IO ()
start config = case protocol config of
  Shadowsocks -> startShadowsocks config
  Trojan -> Server.Transport.Stream.start @Trojan.Context config
  VMess -> Server.Transport.Stream.start @VMess.Context config

startShadowsocks :: ServerConfig -> IO ()
startShadowsocks config = case quic config of
  Just _ -> Server.Transport.Stream.start @Shadowsocks.Context config
  Nothing -> do
    context <- newServerContext config :: IO Shadowsocks.Context
    let startUdp = Server.Transport.Shadowsocks.Datagram.start (label context) config (Shadowsocks.newPacketCodec context)
    void $ concurrently (Server.Transport.Stream.startWithContext context config) startUdp
