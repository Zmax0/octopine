module SetupTest (main) where

import Control.Monad (when)
import Data.Foldable (forM_)
import Data.Maybe (fromJust)
import Distribution.PackageDescription (BuildInfo (extraLibDirs, extraLibs), GenericPackageDescription, HookedBuildInfo, Library (libBuildInfo), PackageDescription (library))
import Distribution.Simple (UserHooks (confHook), defaultMainWithHooks, simpleUserHooks)
import Distribution.Simple.Build.Inputs (LocalBuildInfo (..))
import Distribution.Simple.Setup (ConfigFlags)
import Distribution.Utils.Path (makeSymbolicPath, (<.>), (</>))
import System.Directory (copyFile, createDirectoryIfMissing, doesDirectoryExist, getCurrentDirectory, listDirectory)
import System.FilePath (takeExtension)
import System.Info (os)
import System.Process (callProcess)

main :: IO ()
main = defaultMainWithHooks simpleUserHooks {confHook = configHook'}

configHook' :: (GenericPackageDescription, HookedBuildInfo) -> ConfigFlags -> IO LocalBuildInfo
configHook' (description, buildInfo) flags = do
  let cargoTomlFilePath = rustRootDir </> "Cargo" <.> "toml"
  let cargoBuildCmd =
        if os == "mingw32"
          then ["rustc", "--release", "--crate-type=cdylib", "--manifest-path", cargoTomlFilePath]
          else ["rustc", "--release", "--crate-type=staticlib", "--manifest-path", cargoTomlFilePath]
  putStrLn "Build rust lib ..."
  putStrLn $ unwords cargoBuildCmd
  callProcess "cargo" cargoBuildCmd
  when (os == "mingw32") $ do
    putStrLn "Copying Rust DLLs to target directory..."
    copyRustDlls rustTargetDir finalTargetDir
  localBuildInfo <- confHook simpleUserHooks (description, buildInfo) flags
  let packageDescription = localPkgDescr localBuildInfo
      library' = fromJust $ library packageDescription
      libraryBuildInfo = libBuildInfo library'
  dir <- getCurrentDirectory
  let rsLibDirPath = dir </> "lib" </> "rust" </> "target" </> "release"
  putStrLn $ "Lib dir path -> " ++ rsLibDirPath
  return
    localBuildInfo
      { localPkgDescr =
          packageDescription
            { library =
                Just $
                  library'
                    { libBuildInfo =
                        libraryBuildInfo
                          { extraLibs = ["rs"],
                            extraLibDirs = makeSymbolicPath rsLibDirPath : extraLibDirs libraryBuildInfo
                          }
                    }
            }
      }

rustRootDir :: FilePath
rustRootDir = "lib" </> "rust"

rustTargetDir :: FilePath
rustTargetDir = rustRootDir </> "target" </> "release"

finalTargetDir :: FilePath
finalTargetDir = "target"

copyRustDlls :: FilePath -> FilePath -> IO ()
copyRustDlls sourceDir targetDir = do
  createDirectoryIfMissing True targetDir
  sourceExists <- doesDirectoryExist sourceDir
  when sourceExists $ do
    files <- listDirectory sourceDir
    forM_ (filter ((== ".dll") . takeExtension) files) $ \file -> do
      let src = sourceDir </> file
          dst = targetDir </> file
      copyFile src dst
