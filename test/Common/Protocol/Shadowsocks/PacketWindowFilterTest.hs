module Common.Protocol.Shadowsocks.PacketWindowFilterTest (spec) where

import Common.Protocol.Shadowsocks (PacketId)
import Common.Protocol.Shadowsocks.PacketWindowFilter (empty, reset, validate)
import Control.Monad (forM_)
import Control.Monad.Trans.State (execState, runState)
import Data.IORef (atomicModifyIORef', modifyIORef', newIORef)
import Data.Word (Word64)
import Test.Hspec (Spec, describe, it, shouldReturn)

rejectAfterMessages :: PacketId
rejectAfterMessages = maxBound - 8192

windowSize :: Word64
windowSize = 8128

spec :: Spec
spec =
  describe "Common.Protocol.Shadowsocks.PacketWindowFilter" $ do
    it "validates packet IDs within the replay window" $ do
      packetWindowFilter <- newIORef empty
      let limit = windowSize + 1
          validatePacketId packetId =
            atomicModifyIORef' packetWindowFilter $ \pwf ->
              let (isValid, pwf') = runState (validate packetId rejectAfterMessages) pwf
               in (pwf', isValid)
      validatePacketId 0 `shouldReturn` True
      validatePacketId 1 `shouldReturn` True
      validatePacketId 1 `shouldReturn` False
      validatePacketId 9 `shouldReturn` True
      validatePacketId 8 `shouldReturn` True
      validatePacketId 7 `shouldReturn` True
      validatePacketId 7 `shouldReturn` False
      validatePacketId limit `shouldReturn` True
      validatePacketId (limit - 1) `shouldReturn` True
      validatePacketId (limit - 1) `shouldReturn` False
      validatePacketId (limit - 2) `shouldReturn` True
      validatePacketId 2 `shouldReturn` True
      validatePacketId 2 `shouldReturn` False
      validatePacketId (limit + 16) `shouldReturn` True
      validatePacketId 3 `shouldReturn` False
      validatePacketId (limit + 16) `shouldReturn` False
      validatePacketId (limit * 4) `shouldReturn` True
      validatePacketId (limit * 4 - (limit - 1)) `shouldReturn` True
      validatePacketId 10 `shouldReturn` False
      validatePacketId (limit * 4 - limit) `shouldReturn` False
      validatePacketId (limit * 4 - (limit + 1)) `shouldReturn` False
      validatePacketId (limit * 4 - (limit - 2)) `shouldReturn` True
      validatePacketId (limit * 4 + 1 - limit) `shouldReturn` False
      validatePacketId 0 `shouldReturn` False
      validatePacketId rejectAfterMessages `shouldReturn` False
      validatePacketId (rejectAfterMessages - 1) `shouldReturn` True
      validatePacketId rejectAfterMessages `shouldReturn` False
      validatePacketId (rejectAfterMessages - 1) `shouldReturn` False
      validatePacketId (rejectAfterMessages - 2) `shouldReturn` True
      validatePacketId (rejectAfterMessages + 1) `shouldReturn` False
      validatePacketId (rejectAfterMessages + 2) `shouldReturn` False
      validatePacketId (rejectAfterMessages - 2) `shouldReturn` False
      validatePacketId (rejectAfterMessages - 3) `shouldReturn` True
      validatePacketId 0 `shouldReturn` False

      -- Bulk test 1
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [1 .. windowSize] $ \i -> validatePacketId i `shouldReturn` True
      validatePacketId 0 `shouldReturn` True
      validatePacketId 0 `shouldReturn` False

      -- Bulk test 2
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [2 .. windowSize + 1] $ \i -> validatePacketId i `shouldReturn` True
      validatePacketId 1 `shouldReturn` True
      validatePacketId 0 `shouldReturn` False

      -- Bulk test 3
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [windowSize + 1, windowSize .. 1] $ \i -> validatePacketId i `shouldReturn` True

      -- Bulk test 4
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [windowSize + 2, windowSize + 1 .. 2] $ \i -> validatePacketId i `shouldReturn` True
      validatePacketId 0 `shouldReturn` False

      -- Bulk test 5
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [windowSize, windowSize - 1 .. 1] $ \i -> validatePacketId i `shouldReturn` True
      validatePacketId (windowSize + 1) `shouldReturn` True
      validatePacketId 0 `shouldReturn` False

      -- Bulk test 6
      modifyIORef' packetWindowFilter (execState reset)
      forM_ [windowSize, windowSize - 1 .. 1] $ \i -> validatePacketId i `shouldReturn` True
      validatePacketId 0 `shouldReturn` True
      validatePacketId (windowSize + 1) `shouldReturn` True
