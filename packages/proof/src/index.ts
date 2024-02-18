import calculateNullifierHash from "./calculateNullifierHash"
import generateProof from "./generateProof"
import generateSindriProof from "./generateSindriProof"
import verifyProof from "./verifyProof"

export { MerkleProof } from "@zk-kit/incremental-merkle-tree"
export * from "./types"
export { generateProof, generateSindriProof, verifyProof, calculateNullifierHash }
