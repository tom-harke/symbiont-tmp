
import           Crypto.Hash             (hash, SHA256 (..), Digest)
import           Data.ByteString         (ByteString)
import           Data.Text.Encoding      (encodeUtf8)
import qualified Data.Text.IO            as TIO
import           System.IO               (hFlush, stdout)
import           Data.Int
import           Data.ByteString.Conversion
import           Data.ByteString.Builder
import qualified Data.ByteString.Lazy          as BL
import qualified Data.ByteString               as B

main :: IO ()
main = do
  putStr "Enter some text: "
  hFlush stdout
  text <- TIO.getLine
  let bs = encodeUtf8 text
  putStrLn $ "You entered: " ++ show bs
  let digest :: Digest SHA256
      digest = hash bs
  putStrLn $ "SHA256 hash: " ++ show digest


{- pseudocode from chapter 9 of
      title: Design Principles and Practical Applications
      author:
         - Niels Ferguson
         - Bruce Schneier
         - Tadayoshi Kohno
      isbn: 978-0-470-47424-2
-}


{-
function InitializeGenerator
output: G (Generator state)
  // Set the key K and counter C to zero.
  (K, C) ← (0, 0)
  // Package up the state.
  G ← (K, C)
  return G
-}

type Key      = ByteString
type Counter  = Int32
data GenState = GS { k :: Key, c :: Counter }
   deriving Show

inject = B.concat . BL.toChunks . toByteString . int32BE

initializeGenerator :: GenState
initializeGenerator = GS (inject 0) 0


{-
function Reseed
input: G // Generator state; modified by this function.
       s // New or additional seed.
  // Compute the new key using a hash function.
  K ← SHA_d-256(K||s)
  // Increment the counter to make it nonzero and mark the generator as seeded.
  // Throughout this generator, C is a 16-byte value treated as an integer
  // using the LSByte first convention.
  C ← C + 1
-}

{-
function GenerateBlocks
input: G // Generator state; modified by this function.
       k // Number of blocks to generate.
output: r // Pseudorandom string of 16k bytes.
  assert C = 0
  Start with the empty string.
  r ← ε
  Append the necessary blocks.
  for i = 1,...,k do
    r ← r||E(K, C)
    C ← C + 1
  od
  return r
-}

{-
function PseudoRandomData
input: G // Generator state; modified by this function.
       n // Number of bytes of random data to generate.
output: r // Pseudorandom string of n bytes.
  // Limit the output length to reduce the statistical deviation from perfectly random outputs. Also ensure that the length is not negative.
  assert 0 ≤ n ≤ 2 20
  // Compute the output.
  r ← first-n-bytes(GenerateBlocks(G,ceiling(n/16)))
  // Switch to a new key to avoid later compromises of this output.
  K ← GenerateBlocks(G, 2)
  return r
-}


{-
function InitializePRNG
output: R // prng state.
  // Set the 32 pools to the empty string.
  for i = 0..31 do
    P i ← ε
  od
  // Set the reseed counter to zero.
  ReseedCnt ← 0
  // And initialize the generator.
  G ← InitializeGenerator()
  // Package up the state.
  R ← (G, ReseedCnt, P 0 , . . . , P 31 )
  return R
-}

{-
function RandomData
input: R // prng state, modified by this function.
       n // Number of bytes of random data to generate.
output: r // Pseudorandom string of bytes.
  if length(P 0 ) ≥ MinPoolSize ∧ last reseed > 100 ms ago then
    // We need to reseed.
    ReseedCnt ← ReseedCnt + 1
    // Append the hashes of all the pools we will use.
    s ← ε
    for i ∈ 0, ... , 31 do
      if 2 i | ReseedCnt then
        s ← s || SHAd-256(P_i)
        P_i ← ε
      fi
    od
    // Got the data, now do the reseed.
    Reseed(G, s)
  fi
-}

{-
function AddRandomEvent
input: R // prng state, modified by this function.
       s // Source number in range 0, . . . , 255.
       i // Pool number in range 0, . . . , 31. Each source must distribute its events over all the pools in a round-robin fashion.
       e // Event data. String of bytes; length in range 1, ... 32.
  // Check the parameters first.
  assert 1 ≤ length(e) ≤ 32 ∧ 0 ≤ s ≤ 255 ∧ 0 ≤ i ≤ 31
  // Add the data to the pool.
  P_i ← P_i || s || length(e) || e
-}

{-
function WriteSeedFile
input: R // prng state, modified by this function.
       f // File to write to.
  write(f , RandomData(R, 64))
-}

{-
function UpdateSeedFile
input: R // prng state, modified by this function.
       f // File to be updated.
  s ← read(f )
  assert length(s) = 64
  Reseed(G, s)
  write(f , RandomData(R, 64))
-}
