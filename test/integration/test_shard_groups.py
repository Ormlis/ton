import asyncio
from pathlib import Path

import pytest
from contract import WalletV1Blueprint, ton
from pytoniq_core import Cell, CurrencyCollection
from pytoniq_core.tlb.transaction import ImportFees
from tonlib.tonlibjson import TonlibError
from tontester.install import Install
from tontester.network import Network


def descriptor(data, incoming, key):
    extra = Cell.one_from_boc(data).refs[3]
    records, _ = (
        extra.refs[0 if incoming else 1]
        .begin_parse()
        .load_hashmap_aug_e(
            256,
            lambda entry: entry,
            ImportFees.deserialize if incoming else CurrencyCollection.deserialize,
        )
    )
    return records.get(key)


async def block_for_lt(client, shard, lt):
    while True:
        try:
            return await client.lookup_block(0, shard, lt=lt)
        except TonlibError as error:
            if "LITE_SERVER_NOTREADY" not in str(error):
                raise
            await asyncio.sleep(0.2)


@pytest.mark.parametrize(
    ("grouped", "global_version", "port_base"),
    [(True, 17, 19632), (True, 15, 19664), (False, 17, 19600)],
    ids=["True", "legacy-proofs", "False"],
)
@pytest.mark.asyncio
async def test_cross_shard_delivery(tmp_path, grouped, global_version, port_base):
    repo = Path(__file__).resolve().parents[2]
    install = Install(repo / "build", repo)
    install.tonlibjson.client_set_verbosity_level(1)
    async with (
        asyncio.timeout(150),
        Network(install, tmp_path, port_base=port_base) as net,
    ):
        net.config.split = 1
        net.config.global_version = global_version  # v15 uses legacy proofs, v17 also checks total supply.
        net.config.shard_group_levels = int(grouped)
        net.config.shard_validators = 2
        dht = net.create_dht_node()
        nodes = [net.create_full_node() for _ in range(2)]
        for node in nodes:
            node.make_initial_validator()
            node.announce_to(dht)
        await asyncio.gather(*(node.run() for node in [dht, *nodes]))
        await net.wait_mc_block(1)
        client = await nodes[0].tonlib_client()

        def shard(wallet):
            return -(1 << 62) if wallet.address.hash_part[0] & 128 else 1 << 62

        sender_bp, receiver = WalletV1Blueprint(), WalletV1Blueprint()
        while shard(sender_bp) == shard(receiver):
            receiver = WalletV1Blueprint()
        sender = await net.zerostate.main_wallet(client).deploy(sender_bp, ton(10))
        while (await client.raw_get_account_state(sender.address)).balance <= 0:
            await asyncio.sleep(0.2)
        while (
            len((await client.get_shards((await client.get_masterchain_info()).last)).shards) != 2
        ):
            await asyncio.sleep(0.2)
        await sender.deploy(receiver, ton(1))
        while (dest := await client.raw_get_account_state(receiver.address)).balance <= 0:
            await asyncio.sleep(0.2)
        src = await client.raw_get_account_state(sender.address)
        a, b = await asyncio.gather(
            block_for_lt(client, shard(sender), src.last_transaction_id.lt),
            block_for_lt(client, shard(receiver), dest.last_transaction_id.lt),
        )
        tx = (
            await client.raw_get_transactions(receiver.address, dest.last_transaction_id)
        ).transactions[0]
        key = int.from_bytes(tx.in_msg.hash, "big")
        exported = descriptor(await client.get_block_data(a), False, key)
        imported = descriptor(await client.get_block_data(b), True, key)
        assert exported.load_uint(3) == 0b001
        assert imported.load_uint(5 if grouped else 3) == (0b00110 if grouped else 0b100)
        tx_envelope = exported.load_ref().hash
        assert imported.load_ref().hash == tx_envelope
        if grouped:
            seqno = b.seqno
            while True:
                seqno += 1
                block = await net.wait_block(0, shard(receiver), seqno)
                discard = descriptor(await client.get_block_data(block), True, key)
                if discard is not None:
                    assert discard.load_uint(5) == 0b00111 and discard.remaining_refs == 1
                    assert discard.load_uint(64) == dest.last_transaction_id.lt
                    assert discard.load_ref().hash == tx_envelope
                    break
            while True:
                after = await client.raw_get_account_state(receiver.address)
                heads = (await client.get_shards(after.block_id)).shards
                if any(head.shard == b.shard and head.seqno >= seqno for head in heads):
                    break
                await asyncio.sleep(0.2)
            assert (after.balance, after.last_transaction_id) == (
                dest.balance,
                dest.last_transaction_id,
            )
