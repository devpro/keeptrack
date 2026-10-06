// Triggers a browser save-as for bytes already fetched by C# (a zip export).
// The file exists only in a server-side response, not at a URL the browser could navigate to, so this is the way to hand raw bytes from a Blazor Server component to a download.
window.ktDownloadFile = (fileName, contentType, base64Data) => {
    const link = document.createElement('a');
    link.href = `data:${contentType};base64,${base64Data}`;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    link.remove();
};
