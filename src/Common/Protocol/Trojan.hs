module Common.Protocol.Trojan (getContextKey) where

import Crypto.Hash (hashWith)
import Crypto.Hash.Algorithms (SHA224 (..))
import qualified Data.ByteArray as BA
import qualified Data.ByteString as B
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)

getContextKey :: Text -> B.ByteString
getContextKey = BA.convert . hashWith SHA224 . encodeUtf8
