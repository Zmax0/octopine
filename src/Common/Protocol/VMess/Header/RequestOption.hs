module Common.Protocol.VMess.Header.RequestOption (RequestOption (..), fromMask, toMask) where

import Data.Bits ((.&.))
import GHC.Bits ((.|.))
import GHC.Word (Word8)

-- ConnectionReuse(=2) is deprecated
data RequestOption = Empty | ChunkStream | ChunkMasking | GlobalPadding | AuthenticatedLength deriving (Eq, Show)

toByte :: RequestOption -> Word8
toByte Empty = 0
toByte ChunkStream = 1
toByte ChunkMasking = 4
toByte GlobalPadding = 8
toByte AuthenticatedLength = 16

allOptions :: [RequestOption]
allOptions = [ChunkStream, ChunkMasking, GlobalPadding, AuthenticatedLength]

toMask :: [RequestOption] -> Word8
toMask = foldl' (.|.) 0 . map toByte

fromMask :: Word8 -> [RequestOption]
fromMask mask =
  filter
    ( \opt -> do
        let value = toByte opt
        value /= 0 && (mask .&. value) /= 0
    )
    allOptions

-- hasOption :: RequestOption -> [RequestOption] -> Bool
-- hasOption target options = target `elem` options
