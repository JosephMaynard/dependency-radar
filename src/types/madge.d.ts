declare module 'madge' {
  interface MadgeInstance {
    obj(): Promise<Record<string, string[]>>;
  }

  function madge(entry: string | string[], options?: any): Promise<MadgeInstance>;
  export = madge;
}
