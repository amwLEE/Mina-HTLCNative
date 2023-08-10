import {
    AccountUpdate,
    arrayProp,
    CircuitValue,
    Field,
    method,
    Poseidon,
    PublicKey,
    SmartContract,
    state,
    State,
    Bool,
    UInt64,
    ProvablePure,
    provablePure,
  } from 'snarkyjs';
  
  /**
   * Single Field preimage can fit 4x UInt64, since it can store 256bits
   * TODO: wrap preimage verification and reveal in a separate contract/proof
   * in order to workaround the contract storage limits
   */
  export class Secret extends CircuitValue {
    @arrayProp(Field, 1) value: Field[];
  
    // pattern to allow expanding the preimage to contain 4xUInt64
    static fromUInt64(a: UInt64): Secret {
      const preimage = new Secret();
      // UInt64.toFields() gives us a single field in an array
      // once we add more than 1xUInt64 to the preimage, we will handle the composition into arrayProp here
      preimage.value = a.toFields();
      return preimage;
    }
  }
  
  interface IHTLCNative {
    // mutations which need @method
    newContract(
      receiver: PublicKey,
      amount: UInt64,
      hashlock: Field,
      timelock: UInt64
    ): Field; // emits "LogHTLCNew" event
    withdraw(contractId: Field, preimage: Secret): Bool; // emits "LogHTLCWithdraw" event
    refund(contractId: Field): Bool; // emits "LogHTLCRefund" event

    // pure view functions which don't need @method
    getContract(contractId: Field): (
      sender: PublicKey,
      receiver: PublicKey,
      amount: UInt64,
      hashlock: Field,
      timelock: UInt64,
      withdrawn: Bool,
      refunded: Bool,
      preimage: Secret,
    ) => void;
  
    // events
    events: {
      LogHTLCNew: ProvablePure<{
        contractId: Field;
        sender: PublicKey;
        receiver: PublicKey;
        amount: UInt64;
        hashlock: Field;
        timelock: UInt64;
      }>;
      LogHTLCWithdraw: ProvablePure<{
        contractId: Field;
      }>;
      LogHTLCRefund: ProvablePure<{
        contractId: Field;
      }>;
    };
  }
  
  /**
   * Hash time lock contract using the Poseidon hashing function
   */
  export class HTLCNative extends SmartContract implements IHTLCNative {
    // 2 fields
    @state(PublicKey)
    refundTo: State<PublicKey> = State<PublicKey>();
    // 2 fields
    @state(PublicKey)
    receiver: State<PublicKey> = State<PublicKey>();
    // 1 field
    @state(Field)
    hashlock: State<Field> = State<Field>();
    // 1 field
    @state(UInt64)
    timelock: State<UInt64> = State<UInt64>();
    @state(Bool)
    withdrawn: State<Bool> = State<Bool>();
    @state(Bool)
    refunded: State<Bool> = State<Bool>();
  
    /**
     * Expose preimage through the storage, as it needs to be visible to the
     * second party in case the HTLC is used for an atomic swap.
     *
     * // TODO: replace with 'releasing' the preimage via events, to free up contract on-chain storage
     *
     * IMPORTANT: This only happens at release time, never at lock time.
     */
    @state(Secret)
    preimage: State<Secret> = State<Secret>();
    
    modifierFundsSent(amount: UInt64) {
      amount.assertGreaterThan(UInt64.from(0), "amount must be > 0");
    }

    modifierFutureTimelock(time: UInt64) {
      const timestamp = this.network.timestamp.get();
      this.network.timestamp.assertEquals(timestamp);
      time.assertGreaterThan(timestamp, "timelock time must be in the future");
    }

    modifierContractExists(contractId: Field) {
      this.haveContract(contractId).assertTrue("contractId does not exist");
    }

    modifierHashlockMatches(contractId: Field, preimage: Secret) {
      // check if the preimage results into an identical hash
      const currentHashlock = this.hashlock.get();
      // precondition asserting data consistency between proving and verification
      this.hashlock.assertEquals(currentHashlock);
      const expectedHashlock = Poseidon.hash(preimage.value);
      // assert if the provided preimage matches the preimage used to create the original hashlock
      currentHashlock.assertEquals(expectedHashlock); // "hashlock hash does not match"
    }

    modifierWithdrawable(contractId: Field) {
      const refundTo = this.refundTo.get();
      this.refundTo.assertEquals(refundTo);
      refundTo.assertEquals(this.sender); // "refundable: already refunded"

      const withdrawn = this.withdrawn.get();
      this.withdrawn.assertEquals(withdrawn);
      withdrawn.assertFalse("refundable: already withdrawn");

      const timelock = this.timelock.get();
      this.timelock.assertEquals(timelock);
      const timestamp = this.network.timestamp.get();
      this.network.timestamp.assertEquals(timestamp);
      timelock.assertLessThanOrEqual(timestamp, "refundable: timelock not yet passed");
    }

    modifierRefundable(contractId: Field) {
      const refundTo = this.refundTo.get();
      this.refundTo.assertEquals(refundTo);
      refundTo.assertEquals(this.sender); // "refundable: already refunded"

      const refunded = this.refunded.get();
      this.refunded.assertEquals(refunded);
      refunded.assertFalse("refundable: already refunded");

      const withdrawn = this.withdrawn.get();
      this.withdrawn.assertEquals(withdrawn);
      withdrawn.assertFalse("refundable: already withdrawn");

      const timelock = this.timelock.get();
      this.timelock.assertEquals(timelock);
      const timestamp = this.network.timestamp.get();
      this.network.timestamp.assertEquals(timestamp);
      timelock.assertLessThanOrEqual(timestamp, "refundable: timelock not yet passed");
    }
  
    assertIsNew() {
      const receiver = this.receiver.get();
      this.receiver.assertEquals(receiver);
      // there is no receiver yet
      receiver.isEmpty().assertTrue();
    }
  
    assertIsNotNew() {
      const receiver = this.receiver.get();
      this.receiver.assertEquals(receiver);
      // there is no receiver yet
      receiver.isEmpty().assertFalse();
    }
  
    getRecipient() {
      const receiver = this.receiver.get();
      this.receiver.assertEquals(receiver);
      return receiver;
    }
  
    getRefundTo() {
      const refundTo = this.refundTo.get();
      this.refundTo.assertEquals(refundTo);
      return refundTo;
    }
  
    setHashLock(hashlock: Field) {
      this.hashlock.set(hashlock);
    }
  
    setRecipient(receiver: PublicKey) {
      this.receiver.set(receiver);
    }
  
    setRefundTo(refundTo: PublicKey) {
      this.refundTo.set(refundTo);
    }
  
    setSecret(preimage: Secret) {
      this.preimage.set(preimage);
    }
  
    @method newContract(
      receiver: PublicKey,
      amount: UInt64,
      hashlock: Field,
      timelock: UInt64
    ): Field {
      // console.log('tokenId');
      // Circuit.log(this.tokenId);
      // verify preconditions
      this.assertIsNew();
      this.modifierFundsSent(amount);
      // update state
      this.setRefundTo(this.sender);
      this.setRecipient(receiver);
      this.setHashLock(hashlock);
      // transfer from someone to the contract
      // create an account update for 'from'
      const accountUpdate = AccountUpdate.create(this.sender);
      // sub balance of refundTo with 'amount'
      accountUpdate.balance.subInPlace(amount);
      this.balance.addInPlace(amount);
      // applies a lazy signature a.k.a. to be signed later / outside of the contract
      accountUpdate.sign();
      this.emitEvent('LogHTLCNew', {
        contractId: Field(0),
        sender: this.sender,
        receiver,
        amount,
        hashlock,
        timelock,
      });
      return Field(0);
    }
  
    @method withdraw(contractId: Field, preimage: Secret): Bool {
      // verify preconditions
      // TODO: actually check the state, not just the nonce
      this.assertIsNotNew();
      this.modifierHashlockMatches(contractId, preimage);
  
      this.setSecret(preimage);
  
      const receiver = this.getRecipient();
      // TODO: implement a check for signature of the receiver, disallowing call of 'unlock' without 'being' the receiver
      // this doesnt work for custom tokens, but it works fine for the native token (no token id)
      const accountUpdateRecipient = AccountUpdate.create(
        receiver,
        this.tokenId
      );
  
      accountUpdateRecipient.requireSignature();
  
      // transfer from the contract to the receiver
      const currentBalance = this.account.balance.get();
      // assert balance is equal at time of execution
      this.account.balance.assertEquals(currentBalance);
      // empty out the contract completely
      this.send({
        to: receiver,
        amount: currentBalance,
      });
      this.emitEvent('LogHTLCWithdraw', { contractId });
      return Bool(true);
    }
  
    @method refund(contractId: Field): Bool {
      const timelock = this.timelock.get();
      this.timelock.assertEquals(timelock);
      this.modifierFutureTimelock(timelock);
  
      const refundTo = this.getRefundTo();
      const currentBalance = this.account.balance.get();
      // assert balance is equal at time of execution
      this.account.balance.assertEquals(currentBalance);
      // empty out the contract completely
      this.send({
        to: refundTo,
        amount: currentBalance,
      });
      this.emitEvent('LogHTLCRefund', { contractId });
      return Bool(true);
    }

    getContract(contractId: Field): (
      sender: PublicKey,
      receiver: PublicKey,
      amount: UInt64,
      hashlock: Field,
      timelock: UInt64,
      withdrawn: Bool,
      refunded: Bool,
      preimage: Secret,
    ) => void {
      return (
        sender,
        receiver,
        amount,
        hashlock,
        timelock,
        withdrawn,
        refunded,
        preimage,
      ) => {};
    }

    haveContract(contractId: Field): Bool {
      return Bool(true);
    }

    // events
    events = {
      LogHTLCNew: provablePure({
        contractId: Field,
        sender: PublicKey,
        receiver: PublicKey,
        amount: UInt64,
        hashlock: Field,
        timelock: UInt64,
      }),
      LogHTLCWithdraw: provablePure({
        contractId: Field,
      }),
      LogHTLCRefund: provablePure({
        contractId: Field,
      }),
    };
  }  