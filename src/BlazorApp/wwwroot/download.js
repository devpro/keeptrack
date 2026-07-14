// Triggers a browser save-as for bytes already fetched by C# (e.g. a zip export) - there's no other way
// to hand raw bytes from a Blazor Server component to the browser's download mechanism, since the file
// only exists in the server-side response, not at a public URL the browser could navigate to directly.
window.ktDownloadFile = (fileName, contentType, base64Data) => {
    const link = document.createElement('a');
    link.href = `data:${contentType};base64,${base64Data}`;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
};
