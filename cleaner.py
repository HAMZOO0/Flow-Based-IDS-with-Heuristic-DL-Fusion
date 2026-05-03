import tokenize
import io
import sys

def remove_comments_and_docstrings(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        source = f.read()

    io_obj = io.StringIO(source)
    out = ""
    prev_toktype = tokenize.INDENT
    last_lineno = -1
    last_col = 0
    
    tokens = tokenize.generate_tokens(io_obj.readline)
    
    # We need to handle the case where docstrings are removed but they were the only thing on a line
    # or they were followed by a newline that should also be removed if it becomes redundant.
    # However, to be safe and keep indentation, we'll just replace them with pass if they are standalone,
    # or just remove them if they are not.
    
    modified_tokens = []
    for tok in tokens:
        toktype, ttext, (slineno, scol), (elineno, ecol), ltext = tok
        
        if toktype == tokenize.COMMENT:
            continue
            
        if toktype == tokenize.STRING:
            # Check if it's a docstring:
            # It's a docstring if it's the first statement in a module, class, or function.
            # A simple heuristic: if the previous token was an INDENT, NEWLINE, or NL.
            if prev_toktype in (tokenize.INDENT, tokenize.NEWLINE, tokenize.NL):
                # Check if it's triple-quoted
                if ttext.startswith('"""') or ttext.startswith("'''") or \
                   ttext.startswith('r"""') or ttext.startswith("r'''") or \
                   ttext.startswith('u"""') or ttext.startswith("u'''"):
                    # It's a docstring, skip it
                    prev_toktype = toktype
                    continue
        
        modified_tokens.append(tok)
        prev_toktype = toktype

    # Reconstruct from tokens to preserve as much formatting as possible
    # tokenize.untokenize can be used but it sometimes adds extra spaces.
    # A better way is to manually reconstruct.
    
    res = ""
    last_row, last_col = 1, 0
    for tok in modified_tokens:
        toktype, ttext, (slineno, scol), (elineno, ecol), ltext = tok
        if slineno > last_row:
            res += "\n" * (slineno - last_row)
            last_col = 0
        if scol > last_col:
            res += " " * (scol - last_col)
        res += ttext
        last_row, last_col = elineno, ecol
        
    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(res)

if __name__ == "__main__":
    for path in sys.argv[1:]:
        try:
            remove_comments_and_docstrings(path)
            print(f"Processed {path}")
        except Exception as e:
            print(f"Error processing {path}: {e}")
