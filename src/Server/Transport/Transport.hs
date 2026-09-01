{-# LANGUAGE TemplateHaskell #-}

module Server.Transport.Transport (closePeer) where

import Common.Logger (info_)
import Network.Socket (Socket, close)

closePeer :: Bool -> Socket -> IO ()
closePeer active peer = do
  info_ "Server" $ pure $ if active then ("peer* close" :: String) else "peer close"
  close peer
