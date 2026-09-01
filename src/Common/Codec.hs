module Common.Codec (LeftoverByteString, PendingByteString) where

import Data.ByteString (StrictByteString)

type LeftoverByteString = StrictByteString

type PendingByteString = StrictByteString
