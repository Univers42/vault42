/* ************************************************************************** */
/*                                                                            */
/*                                                          :::      :::::::: */
/*   grpc.rs                                              :+:      :+:    :+: */
/*                                                        +:+ +:+         +:+ */
/*   By: dlesieur <dev.pro.photo@gmail.com>                +#+  +:+       +#+ */
/*                                                          +#+#+#+#+#+   +#+ */
/*   Created: 2026/06/19 00:00:00 by dlesieur                      #+#    #+# */
/*   Updated: 2026/06/19 00:00:00 by dlesieur               ###   ########.fr */
/*                                                                            */
/* ************************************************************************** */

//! The tonic `Vault` trait binding — the generated-contract delegation layer. Every
//! method does the same two mechanical steps: authenticate the signed metadata for its
//! own gRPC method path (binding the signature to the operation), then delegate to a
//! small `op_*` method that holds the real, owner-scoped logic. No business logic lives
//! here; it is the wire-to-logic adapter, kept deliberately thin.

use crate::authn::authn;
use crate::ops_write::WriteOp;
use crate::svc::VaultSvc;
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use vault42_proto::vault::v1::vault_server::Vault;
use vault42_proto::vault::v1::{
    unseal_response, AuditRequest, Chunk, GetRequest, GetResponse, LsRequest, LsResponse,
    PushRequest, PushResponse, RmRequest, RmResponse, RotateKeysRequest, RotateKeysResponse,
    ShareRequest, UnsealRequest, UnsealResponse, WhoamiRequest, WhoamiResponse,
};

type ChunkStream = Pin<Box<dyn Stream<Item = Result<Chunk, Status>> + Send>>;

#[tonic::async_trait]
impl Vault for VaultSvc {
    type FetchStream = ChunkStream;
    type AuditStream = crate::audit_rpc::AuditStream;

    async fn push(&self, request: Request<PushRequest>) -> Result<Response<PushResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Push", self.skew_secs)?;
        let r = request.into_inner();
        let op = WriteOp {
            caller: &caller,
            path: &r.path,
            envelope: &r.envelope,
            expected_prev: r.expected_prev_rev as i64,
            action: "push",
        };
        self.op_write(op).await.map(Response::new)
    }

    async fn get(&self, request: Request<GetRequest>) -> Result<Response<GetResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Get", self.skew_secs)?;
        let r = request.into_inner();
        self.op_get(&caller, &r.path, r.version)
            .await
            .map(Response::new)
    }

    async fn fetch(
        &self,
        request: Request<GetRequest>,
    ) -> Result<Response<Self::FetchStream>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Fetch", self.skew_secs)?;
        let r = request.into_inner();
        let resp = self.op_get(&caller, &r.path, r.version).await?;
        let chunk = Ok(Chunk {
            data: resp.envelope,
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(vec![chunk]))))
    }

    async fn ls(&self, request: Request<LsRequest>) -> Result<Response<LsResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Ls", self.skew_secs)?;
        self.op_ls(&caller, &request.into_inner().prefix)
            .await
            .map(Response::new)
    }

    async fn share(
        &self,
        request: Request<ShareRequest>,
    ) -> Result<Response<PushResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Share", self.skew_secs)?;
        let r = request.into_inner();
        let op = WriteOp {
            caller: &caller,
            path: &r.path,
            envelope: &r.envelope,
            expected_prev: r.expected_prev_rev as i64,
            action: "share",
        };
        self.op_write(op).await.map(Response::new)
    }

    async fn rm(&self, request: Request<RmRequest>) -> Result<Response<RmResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Rm", self.skew_secs)?;
        self.op_rm(&caller, &request.into_inner().path)
            .await
            .map(Response::new)
    }

    async fn rotate(
        &self,
        request: Request<PushRequest>,
    ) -> Result<Response<PushResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Rotate", self.skew_secs)?;
        let r = request.into_inner();
        let op = WriteOp {
            caller: &caller,
            path: &r.path,
            envelope: &r.envelope,
            expected_prev: r.expected_prev_rev as i64,
            action: "rotate",
        };
        self.op_write(op).await.map(Response::new)
    }

    async fn rotate_keys(
        &self,
        request: Request<RotateKeysRequest>,
    ) -> Result<Response<RotateKeysResponse>, Status> {
        let caller = authn(
            request.metadata(),
            "/vault.v1.Vault/RotateKeys",
            self.skew_secs,
        )?;
        let rewrapped = self
            .op_rotate_keys(&caller, request.into_inner().items)
            .await?;
        Ok(Response::new(RotateKeysResponse { rewrapped }))
    }

    async fn audit(
        &self,
        request: Request<AuditRequest>,
    ) -> Result<Response<Self::AuditStream>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Audit", self.skew_secs)?;
        self.op_audit(&caller, request.into_inner().since)
            .await
            .map(Response::new)
    }

    async fn unseal(
        &self,
        request: Request<UnsealRequest>,
    ) -> Result<Response<UnsealResponse>, Status> {
        authn(request.metadata(), "/vault.v1.Vault/Unseal", self.skew_secs)?;
        Ok(Response::new(UnsealResponse {
            state: unseal_response::State::Unsealed as i32,
            progress: 100,
        }))
    }

    async fn whoami(
        &self,
        request: Request<WhoamiRequest>,
    ) -> Result<Response<WhoamiResponse>, Status> {
        let caller = authn(request.metadata(), "/vault.v1.Vault/Whoami", self.skew_secs)?;
        Ok(Response::new(self.op_whoami(&caller)))
    }
}
