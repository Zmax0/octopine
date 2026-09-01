module Common (findArg) where

findArg :: (Eq b) => [b] -> b -> Maybe b
findArg args prefix = do
  lookup prefix (zip args (drop 1 args))
