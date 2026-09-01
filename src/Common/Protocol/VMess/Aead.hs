{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE PatternSynonyms #-}

module Common.Protocol.VMess.Aead
  ( KDFSaltConst
      ( value,
        AuthIDEncryptionKey,
        AEADRespHeaderLenKey,
        AEADRespHeaderLenIV,
        AEADRespHeaderPayloadKey,
        AEADRespHeaderPayloadIV,
        VMessAeadKDF,
        VMessHeaderPayloadAeadKey,
        VMessHeaderPayloadAeadIV,
        VMessHeaderPayloadLengthAeadKey,
        VMessHeaderPayloadLengthAeadIV
      ),
  )
where

import Data.ByteString (StrictByteString)

newtype KDFSaltConst = KDFSaltConst {value :: StrictByteString}

pattern AuthIDEncryptionKey :: KDFSaltConst
pattern AuthIDEncryptionKey = KDFSaltConst "AES Auth ID Encryption"

pattern AEADRespHeaderLenKey :: KDFSaltConst
pattern AEADRespHeaderLenKey = KDFSaltConst "AEAD Resp Header Len Key"

pattern AEADRespHeaderLenIV :: KDFSaltConst
pattern AEADRespHeaderLenIV = KDFSaltConst "AEAD Resp Header Len IV"

pattern AEADRespHeaderPayloadKey :: KDFSaltConst
pattern AEADRespHeaderPayloadKey = KDFSaltConst "AEAD Resp Header Key"

pattern AEADRespHeaderPayloadIV :: KDFSaltConst
pattern AEADRespHeaderPayloadIV = KDFSaltConst "AEAD Resp Header IV"

pattern VMessAeadKDF :: KDFSaltConst
pattern VMessAeadKDF = KDFSaltConst "VMess AEAD KDF"

pattern VMessHeaderPayloadAeadKey :: KDFSaltConst
pattern VMessHeaderPayloadAeadKey = KDFSaltConst "VMess Header AEAD Key"

pattern VMessHeaderPayloadAeadIV :: KDFSaltConst
pattern VMessHeaderPayloadAeadIV = KDFSaltConst "VMess Header AEAD Nonce"

pattern VMessHeaderPayloadLengthAeadKey :: KDFSaltConst
pattern VMessHeaderPayloadLengthAeadKey = KDFSaltConst "VMess Header AEAD Key_Length"

pattern VMessHeaderPayloadLengthAeadIV :: KDFSaltConst
pattern VMessHeaderPayloadLengthAeadIV = KDFSaltConst "VMess Header AEAD Nonce_Length"
