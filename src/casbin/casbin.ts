import { Injectable } from '@nestjs/common';
import { Enforcer, newEnforcer } from 'casbin';
import { join } from 'path';

@Injectable()
export class Casbin {
    
    async enforce(sub: string, obj: string, act: string): Promise<boolean> {
        //TODO: find a way to avoid instantiating a new enforcer each time
        const enforcer = await newEnforcer(join(process.cwd(), './rbac/rbac_model.conf'), join(process.cwd(), './rbac/rbac_policy.csv'))

        return await enforcer.enforce(sub, obj, act)
    }
}
