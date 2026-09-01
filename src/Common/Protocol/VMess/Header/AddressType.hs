{-# LANGUAGE PatternSynonyms #-}

module Common.Protocol.VMess.Header.AddressType (AddressType (IPV4, DOMAIN, IPV6), valueOf) where

import GHC.Word (Word8)

newtype AddressType = AddressType Word8

pattern IPV4 :: AddressType
pattern IPV4 = AddressType 1

pattern DOMAIN :: AddressType
pattern DOMAIN = AddressType 2

pattern IPV6 :: AddressType
pattern IPV6 = AddressType 3

valueOf :: Word8 -> AddressType
valueOf 1 = IPV4
valueOf 2 = DOMAIN
valueOf 3 = IPV6
valueOf other = error $ "unknown address type: " ++ show other
