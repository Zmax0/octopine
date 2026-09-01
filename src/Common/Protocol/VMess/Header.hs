module Common.Protocol.VMess.Header (ID (..), RequestHeader (..), defaultHeader) where

import Common.Network.Address (Address)
import qualified Common.Protocol.VMess as VMess
import Common.Protocol.VMess.Header.RequestCommand (RequestCommand)
import Common.Protocol.VMess.Header.RequestOption (RequestOption)
import qualified Common.Protocol.VMess.Header.RequestOption as RequestOption
import Common.Protocol.VMess.Header.SecurityType (SecurityType)
import Common.Protocol.VMess.ID (newID)
import Common.Util (showBase64)
import Data.ByteString (StrictByteString)
import GHC.Word (Word8)

defaultOptions :: [RequestOption]
defaultOptions = [RequestOption.ChunkStream, RequestOption.ChunkMasking, RequestOption.GlobalPadding, RequestOption.AuthenticatedLength]

newtype ID = ID StrictByteString

instance Show ID where
  show (ID id') = showBase64 id'

data RequestHeader = RequestHeader
  { version :: Word8,
    option :: [RequestOption],
    id :: ID,
    command :: RequestCommand,
    security :: SecurityType,
    address :: Address
  }
  deriving (Show)

defaultHeader :: StrictByteString -> RequestCommand -> SecurityType -> Address -> RequestHeader
defaultHeader uuid = RequestHeader VMess.version defaultOptions (ID $ newID uuid)
