module Common.Protocol.Shadowsocks.AeadTest (spec) where

import Common.Protocol.Shadowsocks.Aead (opensslBytesToKey)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8
import Test.Hspec (Spec, describe, it, shouldBe)

spec :: Spec
spec =
  describe "Common.Protocol.Shadowsocks.Aead" $ do
    it "opensslBytesToKey" $ do
      let password = C8.pack "Personal search-enabled assistant for programmers"
          key = C8.unpack $ B64.encode $ opensslBytesToKey password 16
      key `shouldBe` "zsWfM5hwvmTusK6sGOop5w=="

      let password' = C8.pack "Personal search-enabled assistant for programmers"
          key' = C8.unpack $ B64.encode $ opensslBytesToKey password' 32
      key' `shouldBe` "zsWfM5hwvmTusK6sGOop57hBNhUblVO/PpBKSm34Vu4="
