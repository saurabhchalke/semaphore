import { BigNumber } from "@ethersproject/bignumber"
import { BytesLike, Hexable } from "@ethersproject/bytes"
import { Group } from "@semaphore-protocol/group"
import type { Identity } from "@semaphore-protocol/identity"
import { Groth16Proof, PublicSignals, prove } from "@zk-kit/groth16"
import { MerkleProof } from "@zk-kit/incremental-merkle-tree"
import type { NumericString } from "snarkjs"
import hash from "./hash"
import packProof from "./packProof"
import { SemaphoreProof, SnarkArtifacts } from "./types"
// @ts-ignore
import { unstringifyBigInts } from "./utils"

// Define constants for the API
const API_URL = "https://sindri.app/api/v1"
const TIMEOUT = 120 // Timeout after 2 minutes
const headers = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${process.env.NEXT_PUBLIC_SINDRI_API_KEY}`
}
const headersPost = {
    "Content-Type": "application/x-www-form-urlencoded",
    Authorization: `Bearer ${process.env.NEXT_PUBLIC_SINDRI_API_KEY}`
}

/**
 * Generates a Semaphore proof.
 * @param identity The Semaphore identity.
 * @param groupOrMerkleProof The Semaphore group or its Merkle proof.
 * @param externalNullifier The external nullifier.
 * @param signal The Semaphore signal.
 * @param snarkArtifacts The SNARK artifacts.
 * @returns The Semaphore proof ready to be verified.
 */
export default async function generateProof(
    { trapdoor, nullifier, commitment }: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    externalNullifier: BytesLike | Hexable | number | bigint,
    signal: BytesLike | Hexable | number | bigint,
    circuitId: string,
    snarkArtifacts?: SnarkArtifacts
): Promise<SemaphoreProof> {
    let merkleProof: MerkleProof

    if ("depth" in groupOrMerkleProof) {
        const index = groupOrMerkleProof.indexOf(commitment)

        if (index === -1) {
            throw new Error("The identity is not part of the group")
        }

        merkleProof = groupOrMerkleProof.generateMerkleProof(index)
    } else {
        merkleProof = groupOrMerkleProof
    }

    if (!snarkArtifacts) {
        snarkArtifacts = {
            wasmFilePath: `https://www.trusted-setup-pse.org/semaphore/${merkleProof.siblings.length}/semaphore.wasm`,
            zkeyFilePath: `https://www.trusted-setup-pse.org/semaphore/${merkleProof.siblings.length}/semaphore.zkey`
        }
    }

    const inputSignals = {
        identityTrapdoor: trapdoor,
        identityNullifier: nullifier,
        treePathIndices: merkleProof.pathIndices,
        treeSiblings: merkleProof.siblings,
        externalNullifier: hash(externalNullifier),
        signalHash: hash(signal)
    }

    // Make a request to the Sindri API to generate the proof
    const serializedInputSignals = JSON.stringify(
        unstringifyBigInts(inputSignals),
        (key, value) => (typeof value === "bigint" ? value.toString() : value) // Convert BigInt to string
    )

    const proofResponse = await fetch(`${API_URL}/circuit/${circuitId}/prove`, {
        method: "POST",
        headers: headersPost,
        body: new URLSearchParams({ proof_input: serializedInputSignals })
    }).then((res) => res.json())

    // if (proofResponse?.status_code !== 201) {
    //     throw new Error("Failed to initiate proof generation")
    // }

    const proofId = proofResponse.proof_id

    console.log("proofId", proofId)

    // Poll the proof status
    let actionComplete = false
    let proofDetail

    for (let i = 0; i < TIMEOUT; i += 1) {
        const pollResponse = await fetch(`${API_URL}/proof/${proofId}/detail`, { headers }).then((res) => res.json())
        const { status } = pollResponse
        if (status === "Ready" || status === "Failed") {
            console.log(`Proof poll exited after ${i} seconds with status: ${status}`)
            actionComplete = true
            if (status === "Ready") {
                proofDetail = pollResponse
            }
            break
        }

        // eslint-disable-next-line no-promise-executor-return
        await new Promise((resolve) => setTimeout(resolve, 1000))
    }

    if (!actionComplete) {
        throw new Error("Proof polling timed out")
    }

    if (!proofDetail) {
        throw new Error("Proving failed")
    }

    // Deserialize the proof and public inputs from the API response
    const proof: Groth16Proof = {
        pi_a: proofDetail.proof.pi_a,
        pi_b: proofDetail.proof.pi_b,
        pi_c: proofDetail.proof.pi_c,
        protocol: "groth16",
        curve: "bn128"
    }

    const publicSignals: PublicSignals = proofDetail.public

    // Print the proof and public inputs
    console.log("proof", JSON.stringify(proof))
    console.log("publicSignals", JSON.stringify(publicSignals))

    // const { proof, publicSignals } = await prove(
    //     {
    //         identityTrapdoor: trapdoor,
    //         identityNullifier: nullifier,
    //         treePathIndices: merkleProof.pathIndices,
    //         treeSiblings: merkleProof.siblings,
    //         externalNullifier: hash(externalNullifier),
    //         signalHash: hash(signal)
    //     },
    //     snarkArtifacts.wasmFilePath,
    //     snarkArtifacts.zkeyFilePath
    // )

    return {
        merkleTreeRoot: publicSignals[0],
        nullifierHash: publicSignals[1],
        signal: BigNumber.from(signal).toString() as NumericString,
        externalNullifier: BigNumber.from(externalNullifier).toString() as NumericString,
        proof: packProof(proof)
    }
}
