package cli

type baseCryptFlags struct {
	DecryptFlag  bool   `arg:"-d,--decrypt" default:"false" help:"Decrypt mode"`
	StdinFlag    bool   `arg:"--stdin" default:"false" help:"Use stdin as input"`
	StdoutFlag   bool   `arg:"--stdout" default:"false" help:"Write output to stdout"`
	StdinText    bool   `arg:"-t,--text" default:"false" help:"Enter a text line manually to stdin"`
	InfileFlag   string `arg:"-i,--infile" placeholder:"IN" help:"Input filename, stdin if omitted"`
	EncodingFlag string `arg:"-e,--encoding" placeholder:"ENC" help:"'base64' or 'hex' encoding for input or output"`
	OutfileFlag  string `arg:"-o,--outfile" placeholder:"OUT" help:"Output filename, stdout if omitted"`
}

type Args struct {
	AESCommand *aesCommand `arg:"subcommand:aes"`
	RSACommand *rsaCommand `arg:"subcommand:rsa"`
}
