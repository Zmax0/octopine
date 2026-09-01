{-# LANGUAGE PatternSynonyms #-}

module Common.Protocol.VMess.Header.RequestCommand (RequestCommand (RequestCommand, TCP, UDP)) where

import GHC.Word (Word8)

newtype RequestCommand = RequestCommand Word8 deriving (Eq, Show)

pattern TCP :: RequestCommand
pattern TCP = RequestCommand 1

pattern UDP :: RequestCommand
pattern UDP = RequestCommand 2

-- not support Mux now
