module Main (main) where

import qualified Common.Codec.Shadowsocks.Aead2022.TCPTest
import qualified Common.Codec.Socks.AddressTest
import qualified Common.Codec.VMess.AeadTest
import qualified Common.Codec.VMess.ShakeSizeParserTest
import qualified Common.Crypto.Aead.NonceGeneratorTest
import qualified Common.Crypto.AeadTest
import qualified Common.Lang.GoTest
import qualified Common.Protocol.Shadowsocks.Aead2022Test
import qualified Common.Protocol.Shadowsocks.AeadTest
import qualified Common.Protocol.Shadowsocks.PacketWindowFilterTest
import qualified Common.Protocol.Shadowsocks.UserTest
import qualified Common.Protocol.VMess.Aead.AuthIDTest
import qualified Common.Protocol.VMess.Aead.KDFTest
import qualified Common.Protocol.VMess.IDTest
import qualified Common.UtilTest
import Test.Hspec (hspec)

main :: IO ()
main =
  hspec $ do
    Common.Codec.Socks.AddressTest.spec
    Common.Crypto.Aead.NonceGeneratorTest.spec
    Common.Codec.Shadowsocks.Aead2022.TCPTest.spec
    Common.Codec.VMess.AeadTest.spec
    Common.Codec.VMess.ShakeSizeParserTest.spec
    Common.Crypto.AeadTest.spec
    Common.Lang.GoTest.spec
    Common.Protocol.Shadowsocks.Aead2022Test.spec
    Common.Protocol.Shadowsocks.AeadTest.spec
    Common.Protocol.Shadowsocks.PacketWindowFilterTest.spec
    Common.Protocol.Shadowsocks.UserTest.spec
    Common.Protocol.VMess.Aead.AuthIDTest.spec
    Common.Protocol.VMess.Aead.KDFTest.spec
    Common.Protocol.VMess.IDTest.spec
    Common.UtilTest.spec
