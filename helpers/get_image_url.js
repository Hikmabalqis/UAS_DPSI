function getImageUrl(protocol, host, buku) {
  return `${protocol}://${host}/buku/${buku.id}/image`;
}

module.exports = getImageUrl;
