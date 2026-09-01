module Common.Protocol.VMess.Header.SecurityType (SecurityType (..), valueOf) where

import qualified Common.Crypto.Aead as Aead

data SecurityType = Unknown | Legacy | Auto | Aes128Gcm | ChaCha20Poly1305 | None | Zero deriving (Show, Eq, Ord, Bounded)

instance Enum SecurityType where
  fromEnum Unknown = 0
  fromEnum Legacy = 1
  fromEnum Auto = 2
  fromEnum Aes128Gcm = 3
  fromEnum ChaCha20Poly1305 = 4
  fromEnum None = 5
  fromEnum Zero = 6

  toEnum 1 = Legacy
  toEnum 2 = Auto
  toEnum 3 = Aes128Gcm
  toEnum 4 = ChaCha20Poly1305
  toEnum 5 = None
  toEnum 6 = Zero
  toEnum _ = Unknown

valueOf :: Aead.CipherKind -> SecurityType
valueOf Aead.ChaCha20Poly1305 = ChaCha20Poly1305
valueOf _ = Aes128Gcm
