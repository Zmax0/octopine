module Common.Protocol.Shadowsocks.Aead (hkdfsha1, opensslBytesToKey) where

import Common.Crypto (Key)
import Common.Protocol.Shadowsocks (Salt (Salt))
import Crypto.Hash (hashWith)
import Crypto.Hash.Algorithms (MD5 (MD5), SHA1)
import qualified Crypto.KDF.HKDF as HKDF
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as C8

hkdfsha1 :: Key -> Salt -> Key
hkdfsha1 ikm (Salt salt) = HKDF.expand (HKDF.extract salt ikm :: HKDF.PRK SHA1) (C8.pack "ss-subkey") (B.length salt)

opensslBytesToKey :: B.ByteString -> Int -> Key
opensslBytesToKey password size = go B.empty Nothing
  where
    go acc last' =
      let (_, newLast) = case last' of
            Nothing -> (password, md5 password)
            Just l -> let input' = B.append l password in (input', md5 input')
          addLen = min (size - B.length acc) (B.length newLast)
          partToAdd = B.take addLen newLast
          newAcc = B.append acc partToAdd
       in if B.length newAcc >= size
            then B.take size newAcc
            else go newAcc (Just newLast)

md5 :: B.ByteString -> B.ByteString
md5 bytes = do
  let digest = hashWith MD5 bytes
  BA.convert digest
