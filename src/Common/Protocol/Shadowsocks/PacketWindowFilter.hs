module Common.Protocol.Shadowsocks.PacketWindowFilter (PacketWindowFilter, empty, new, validate, reset) where

import Common.Protocol.Shadowsocks (PacketId)
import Control.Monad.Trans.State (State, get, put)
import Data.Bits (Bits ((.&.), (.|.)), (.<<.), (.>>.))
import Data.Vector.Unboxed (Vector)
import qualified Data.Vector.Unboxed as V
import Data.Word (Word64)

bitmapLength :: Int
bitmapLength = 128

redundantBitShifts :: Int
redundantBitShifts = 6 -- 1 << 6 == 64 bits

blockMask :: Word64
blockMask = fromIntegral bitmapLength - 1

bitMask :: Word64
bitMask = 63

defaultWindowSize :: Word64
defaultWindowSize = (fromIntegral bitmapLength - 1) * 64

data PacketWindowFilter = PacketWindowFilter
  { bitmap :: !(Vector Word64),
    lastId :: !PacketId,
    windowSize :: !Word64
  }
  deriving (Show)

empty :: PacketWindowFilter
empty = PacketWindowFilter (V.replicate bitmapLength 0) 0 defaultWindowSize

new :: PacketId -> Word64 -> PacketWindowFilter
new lastId' windowSize' = empty {lastId = lastId', windowSize = windowSize'}

validate :: PacketId -> PacketId -> State PacketWindowFilter Bool
validate id' limit = do
  pwf <- get
  validateWith pwf
  where
    validateWith pwf
      | id' >= limit = pure False
      | id' > lastId pwf =
          let current = lastId pwf .>>. redundantBitShifts
              idx = id' .>>. redundantBitShifts
              diff0 = idx - current
              diff =
                if diff0 > fromIntegral bitmapLength
                  then fromIntegral bitmapLength
                  else diff0
              updates = [(fromIntegral ((d + current) .&. blockMask), 0) | d <- [1 .. diff]]
              bmp' = bitmap pwf V.// updates
              pwf' = pwf {bitmap = bmp', lastId = id'}
           in checkAndSet id' pwf'
      | id' + windowSize pwf < lastId pwf = pure False
      | otherwise = checkAndSet id' pwf
    checkAndSet pid p =
      let bmp = bitmap p
          idx = fromIntegral ((pid .>>. redundantBitShifts) .&. blockMask)
          bitLoc = fromIntegral (pid .&. bitMask)
          val = bmp V.! idx
          bitVal = 1 .<<. bitLoc
       in if val .&. bitVal /= 0
            then pure False
            else put (p {bitmap = bmp V.// [(idx, val .|. bitVal)]}) >> pure True

reset :: State PacketWindowFilter ()
reset = do
  pwf <- get
  put (pwf {lastId = 0, bitmap = V.replicate bitmapLength 0})
