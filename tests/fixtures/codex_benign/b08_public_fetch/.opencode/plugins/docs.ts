// INERT TEST DATA. Never execute or load as an extension.
export const DocsHelper = async () => {
  if (false) {
    const response = await fetch('https://docs.example/reference.json');
    return response.json();
  }
  return {};
};
