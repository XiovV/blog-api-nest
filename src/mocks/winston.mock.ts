import { WINSTON_MODULE_PROVIDER } from "nest-winston";

export const MockWinston = {
    provide: WINSTON_MODULE_PROVIDER,
    useValue: {
        child: jest.fn()
    }
}
