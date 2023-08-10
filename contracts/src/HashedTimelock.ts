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
   * Single Field secret can fit 4x UInt64, since it can store 256bits
   * TODO: wrap secret verification and reveal in a separate contract/proof
   * in order to workaround the contract storage limits
   */
  export class Secret extends CircuitValue {
    @arrayProp(Field, 1) value: Field[];
  
    // pattern to allow expanding the secret to contain 4xUInt64
    static fromUInt64(a: UInt64): Secret {
      const secret = new Secret();
      // UInt64.toFields() gives us a single field in an array
      // once we add more than 1xUInt64 to the secret, we will handle the composition into arrayProp here
      secret.value = a.toFields();
      return secret;
    }
  }
  
  interface HTLCPoseidonConcrete {
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
  export abstract class HTLCPoseidon extends SmartContract implements HTLCPoseidonConcrete {
    // 2 fields
    @state(PublicKey)
    refundTo: State<PublicKey> = State<PublicKey>();
    // 2 fields
    @state(PublicKey)
    recipient: State<PublicKey> = State<PublicKey>();
    // 1 field
    @state(Field)
    hashlock: State<Field> = State<Field>();
    // 1 field
    @state(UInt64)
    expireAt: State<UInt64> = State<UInt64>();
  
    /**
     * Expose secret through the storage, as it needs to be visible to the
     * second party in case the HTLC is used for an atomic swap.
     *
     * // TODO: replace with 'releasing' the secret via events, to free up contract on-chain storage
     *
     * IMPORTANT: This only happens at release time, never at lock time.
     */
    @state(Secret)
    secret: State<Secret> = State<Secret>();
  
    assertExpiresAtSufficientFuture(expireAt: UInt64) {
      const timestamp = this.network.timestamp.get();
      this.network.timestamp.assertEquals(timestamp);
      // assert that expiresAt is at least 3 days in the future
      // TODO: should we use absolute value for expireAt, or relative to timestamp?
      // e.g. expireAt = timestamp+expireAt
      
      const oneDay = UInt64.from(86400000);
      const expireSubThreeDays =
      Array(3)
        .fill(null)
        .reduce((expireAt) => {
          return expireAt.sub(oneDay);
        }, expireAt);
      //const expireSubThreeDays = subDays(expireAt, 3);
      expireSubThreeDays.assertGreaterThan(timestamp);
    }
  
    assertDepositAmountNotZero(amount: UInt64) {
      amount.assertGreaterThan(UInt64.from(0));
    }
  
    assertIsNew() {
      const recipient = this.recipient.get();
      this.recipient.assertEquals(recipient);
      // there is no recipient yet
      recipient.isEmpty().assertTrue();
    }
  
    assertIsNotNew() {
      const recipient = this.recipient.get();
      this.recipient.assertEquals(recipient);
      // there is no recipient yet
      recipient.isEmpty().assertFalse();
    }
  
    assertIsExpired() {
      const timestamp = this.network.timestamp.get();
      this.network.timestamp.assertEquals(timestamp);
      const expireAt = this.expireAt.get();
      this.expireAt.assertEquals(expireAt);
  
      // TODO: should we use assertLessThan instead?
      expireAt.assertLessThanOrEqual(timestamp);
    }
  
    getRecipient() {
      const recipient = this.recipient.get();
      this.recipient.assertEquals(recipient);
      return recipient;
    }
  
    getRefundTo() {
      const refundTo = this.refundTo.get();
      this.refundTo.assertEquals(refundTo);
      return refundTo;
    }
  
    setHashLock(hashlock: Field) {
      this.hashlock.set(hashlock);
    }
  
    setRecipient(recipient: PublicKey) {
      this.recipient.set(recipient);
    }
  
    setRefundTo(refundTo: PublicKey) {
      this.refundTo.set(refundTo);
    }
  
    setSecret(secret: Secret) {
      this.secret.set(secret);
    }
  
    assertSecretHashEqualsHashlock(secret: Secret) {
      // check if the secret results into an identical hash
      const currentHashlock = this.hashlock.get();
      // precondition asserting data consistency between proving and verification
      this.hashlock.assertEquals(currentHashlock);
      const expectedHashlock = Poseidon.hash(secret.value);
      // assert if the provided secret matches the secret used to create the original hashlock
      currentHashlock.assertEquals(expectedHashlock);
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
      this.assertExpiresAtSufficientFuture(timelock);
      this.assertDepositAmountNotZero(amount);
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
      this.assertSecretHashEqualsHashlock(preimage);
  
      this.setSecret(preimage);
  
      const recipient = this.getRecipient();
      // TODO: implement a check for signature of the recipient, disallowing call of 'unlock' without 'being' the recipient
      // this doesnt work for custom tokens, but it works fine for the native token (no token id)
      const accountUpdateRecipient = AccountUpdate.create(
        recipient,
        this.tokenId
      );
  
      accountUpdateRecipient.requireSignature();
  
      // transfer from the contract to the recipient
      const currentBalance = this.account.balance.get();
      // assert balance is equal at time of execution
      this.account.balance.assertEquals(currentBalance);
      // empty out the contract completely
      this.send({
        to: recipient,
        amount: currentBalance,
      });
      this.emitEvent('LogHTLCWithdraw', { contractId });
      return Bool(true);
    }
  
    @method refund(contractId: Field): Bool {
      this.assertIsExpired();
  
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