export interface TransactionCommon {
  id: string;
  inputs: {
    fulfillment: string;
    fulfills: {
      output_index: number;
      transaction_id: string;
    } | null;
    owners_before: string[];
  }[];
  outputs: {
    amount: string;
    condition: any[];
    public_keys: string[];
  }[];
  version: string;
  metadata: {
    [key: string]: unknown;
  };
}

export interface TransferTransaction extends TransactionCommon {
  asset: {
    id: string;
  };
  operation: 'TRANSFER';
}

export interface CreateTransaction<T> extends TransactionCommon {
  asset: {
    data: T;
  };
  operation: 'CREATE';
}

export declare type Transaction<T> = TransferTransaction | CreateTransaction<T>;
