import { mkdtemp,writeFile,mkdir,symlink,rm,realpath } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { expect,it } from 'vitest';
import { restrictedPartnerResources } from '../restrictedPartnerResources.js';
import type { RestrictedPartnerGrant } from '../restrictedPartnerExecution.js';
it('real approved-resource helper reads only selected facts and denies traversal, symlink and revocation',async()=>{
 const root=await realpath(await mkdtemp(path.join(tmpdir(),'restricted-partner-resource-')));let valid=true;
 try{
  await mkdir(path.join(root,'approved'));await writeFile(path.join(root,'approved','facts.md'),'APPROVED_PERSISTENT_FACT');await writeFile(path.join(root,'private.md'),'PRIVATE_OWNER_CONTEXT');await symlink(path.join(root,'private.md'),path.join(root,'approved','escape.md'));
  const g={resources:[{id:'resource-1',path:path.join(root,'approved')}]} as RestrictedPartnerGrant;
  const p=restrictedPartnerResources(g,()=>{if(!valid)throw Error('REVOKED');});
  const read=p.tools.find(x=>x.name==='partner_resource_read')!;
  const good=await read.invoke({resourceId:'resource-1',relativePath:'facts.md'},{callId:'call',runId:'run'});
  expect(good.success).toBe(true);expect(JSON.stringify(good)).toContain('APPROVED_PERSISTENT_FACT');
  for(const relativePath of ['../private.md','escape.md']){
   const denied=await read.invoke({resourceId:'resource-1',relativePath},{callId:'call',runId:'run'});expect(denied.success).toBe(false);expect(JSON.stringify(denied)).not.toContain('PRIVATE_OWNER_CONTEXT');
  }
  await expect(read.invoke({resourceId:'other',relativePath:'facts.md'},{callId:'call',runId:'run'})).rejects.toThrow('DENIED');
  valid=false;await expect(read.invoke({resourceId:'resource-1',relativePath:'facts.md'},{callId:'call',runId:'run'})).rejects.toThrow('REVOKED');
 }finally{await rm(root,{recursive:true,force:true});}
});
