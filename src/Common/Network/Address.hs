{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}

module Common.Network.Address (Address (..), parseAddr) where

import qualified Data.List.NonEmpty as NE
import Data.Text (Text)
import qualified Data.Text as T
import Data.Word (Word16)
import Network.Socket (AddrInfo (addrAddress, addrFlags, addrSocketType), AddrInfoFlag (AI_PASSIVE), HostName, ServiceName, SockAddr, SocketType (Stream), defaultHints, getAddrInfo)

data Address = Domain Text Word16 | SockAddr SockAddr

instance Show Address where
  show (Domain host port) = T.unpack host ++ ":" ++ show port
  show (SockAddr addr) = show addr

parseAddr :: Address -> IO SockAddr
parseAddr (Domain host' port') = return <$> addrAddress =<< dnsQuery (T.unpack host') (show port')
parseAddr (SockAddr socketAddr) = return socketAddr

dnsQuery :: HostName -> ServiceName -> IO AddrInfo
dnsQuery host' port' = do
  let hints = defaultHints {addrFlags = [AI_PASSIVE], addrSocketType = Stream}
  NE.head <$> getAddrInfo (Just hints) (Just host') (Just port')
