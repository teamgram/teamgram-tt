import { useState } from '../lib/teact/teact';

import useThrottle from './useThrottle';
import useOnChange from './useOnChange';
import useHeavyAnimationCheck from './useHeavyAnimationCheck';
import useFlag from './useFlag';

export default function useThrottledMemo<R extends any, D extends any[]>(
  resolverFn: () => R, ms: number, dependencies: D,
): R | undefined {
  const runThrottled = useThrottle(ms, true);
  const [value, setValue] = useState<R>();
  const [isFrozen, freeze, unfreeze] = useFlag();

  useHeavyAnimationCheck(freeze, unfreeze);

  useOnChange(() => {
    if (isFrozen) {
      return;
    }

    runThrottled(() => {
      setValue(resolverFn());
    });
  }, [...dependencies, isFrozen]);

  return value;
}
