module Main (main) where

import Common.Config (initConfig)
import Common.Logger (info_, initRootLevel)
import Control.Concurrent.Async (mapConcurrently_)
import Server (start)
import System.Environment (getArgs)

main :: IO ()
main = do
  args <- getArgs
  initRootLevel args
  initConfig args >>= mapConcurrently_ start
  info_ "Main" $ return "terminated"
