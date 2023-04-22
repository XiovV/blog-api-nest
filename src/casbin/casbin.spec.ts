import { Test, TestingModule } from '@nestjs/testing';
import { Casbin } from './casbin';

describe('Casbin', () => {
  let provider: Casbin;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [Casbin],
    }).compile();

    provider = module.get<Casbin>(Casbin);
  });

  it('should be defined', () => {
    expect(provider).toBeDefined();
  });
});
