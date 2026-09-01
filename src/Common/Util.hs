module Common.Util (decodeWord16BE, decodeWord64BE, encodeLengthWord16be, encodeWord16BE, encodeWord64BE, showBase64, showByteString, showUnpack, sockAddrFamily) where

import Data.Bits (shiftL, shiftR, (.|.))
import Data.ByteString (StrictByteString)
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as C8
import qualified Data.ByteString.Internal as BI
import Data.Char (chr)
import Data.Word (Word16, Word64, Word8)
import Foreign (pokeElemOff)
import Network.Socket (Family (AF_INET, AF_INET6, AF_UNIX), SockAddr (SockAddrInet, SockAddrInet6, SockAddrUnix))
import Numeric (showHex)

encodeWord16BE :: Int -> StrictByteString
encodeWord16BE value =
  let word = fromIntegral value :: Word16
   in BI.unsafeCreate 2 $ \ptr -> do
        pokeElemOff ptr 0 (fromIntegral (word `shiftR` 8) :: Word8)
        pokeElemOff ptr 1 (fromIntegral word :: Word8)

decodeWord16BE :: StrictByteString -> Int
decodeWord16BE bytes =
  let hi = fromIntegral $ B.index bytes 0
      lo = fromIntegral $ B.index bytes 1
   in hi * 256 + lo

encodeWord64BE :: Word64 -> StrictByteString
encodeWord64BE word =
  BI.unsafeCreate 8 $ \ptr -> do
    pokeElemOff ptr 0 (fromIntegral (word `shiftR` 56) :: Word8)
    pokeElemOff ptr 1 (fromIntegral (word `shiftR` 48) :: Word8)
    pokeElemOff ptr 2 (fromIntegral (word `shiftR` 40) :: Word8)
    pokeElemOff ptr 3 (fromIntegral (word `shiftR` 32) :: Word8)
    pokeElemOff ptr 4 (fromIntegral (word `shiftR` 24) :: Word8)
    pokeElemOff ptr 5 (fromIntegral (word `shiftR` 16) :: Word8)
    pokeElemOff ptr 6 (fromIntegral (word `shiftR` 8) :: Word8)
    pokeElemOff ptr 7 (fromIntegral word :: Word8)

decodeWord64BE :: StrictByteString -> Word64
decodeWord64BE bytes =
  let byte0 = fromIntegral $ B.index bytes 0
      byte1 = fromIntegral $ B.index bytes 1
      byte2 = fromIntegral $ B.index bytes 2
      byte3 = fromIntegral $ B.index bytes 3
      byte4 = fromIntegral $ B.index bytes 4
      byte5 = fromIntegral $ B.index bytes 5
      byte6 = fromIntegral $ B.index bytes 6
      byte7 = fromIntegral $ B.index bytes 7
   in byte0 `shiftL` 56 .|. byte1 `shiftL` 48 .|. byte2 `shiftL` 40 .|. byte3 `shiftL` 32 .|. byte4 `shiftL` 24 .|. byte5 `shiftL` 16 .|. byte6 `shiftL` 8 .|. byte7

encodeLengthWord16be :: StrictByteString -> StrictByteString
encodeLengthWord16be = encodeWord16BE . B.length

showBase64 :: StrictByteString -> String
showBase64 = C8.unpack . B64.encode

showByteString :: StrictByteString -> String
showByteString bytes =
  "b\""
    ++ concatMap
      ( \byte -> case byte of
          9 -> "\\t"
          10 -> "\\n"
          13 -> "\\r"
          34 -> "\\\""
          39 -> "\\'"
          92 -> "\\\\"
          _
            | byte >= 0x20 && byte <= 0x7e -> [chr $ fromIntegral byte]
            | otherwise ->
                "\\x" ++ case showHex byte "" of
                  [digit] -> ['0', digit]
                  digits -> digits
      )
      (B.unpack bytes)
    ++ "\""

showUnpack :: StrictByteString -> String
showUnpack = show . B.unpack

sockAddrFamily :: SockAddr -> Family
sockAddrFamily SockAddrInet {} = AF_INET
sockAddrFamily SockAddrInet6 {} = AF_INET6
sockAddrFamily SockAddrUnix {} = AF_UNIX
