module sha256one #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr,
 output logic done, mem_clk, mem_we,
 output logic [15:0] mem_addr,
 output logic [31:0] hout [16][8],
 input logic [31:0] mem_read_data,
 input logic[31:0] h0_in, h1_in, h2_in, h3_in, h4_in, h5_in, h6_in, h7_in,
 output logic[31:0] h0_out, h1_out, h2_out, h3_out, h4_out, h5_out, h6_out, h7_out
 output logic [32:0] w0,w1,w2,w3
);
// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16];
logic [31:0] message[20]; // only 20 words but add 12 for padding
// logic [31:0] wt; // not used
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7; // first block hash values
logic [31:0] sh0, sh1, sh2, sh3, sh4, sh5, sh6, sh7; // second block hash values
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i; // used as index for making case statements mimick for loop functionality
logic [ 7:0] j, n; // used as index for which block is being processed
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
// logic [512:0] memory_block; // not used
// logic [ 7:0] tstep; // not used
logic   [31:0] s1, s0;
logic [4:0] nonce;

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
// assign tstep = (i - 1); // not used

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] num_words);
  logic [64:0] full_len; // max message length (2^64) + num of padding bits
  logic [15:0] num_blocks;
  
  // Student to add function implementation
  full_len = (num_words * 32) + 1 + 64; // message bits + all padding bits
  num_blocks = full_len / 512;
  if (full_len % 512 != 0) begin
		num_blocks = num_blocks + 1;
		return num_blocks;
  end
  else begin
		return num_blocks;
  end  

endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
	logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals

	S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
	// Student to add remaning code below
	// Refer to SHA256 discussion slides to get logic for this function
	ch = (e & f) ^ ((~e) & g);
	t1 = h + S1 + ch + k[t] + w;
	S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
	maj = (a & b) ^ (a & c) ^ (b & c);
	t2 = S0 + maj;
	sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};

endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
	rightrotate = (x >> r) | (x << (32 - r));
endfunction

function logic [31:0] wtnew; // W[n] word expansion array seen in discussion
	logic [31:0] s1, s0; // internal signals
	begin
		s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1] >> 3);
		s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19) ^ (w[14] >> 10);
		wtnew = w[0] + s0 + w[9] + s1;
	end
endfunction

// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n) begin
	if (!reset_n) begin
		cur_we <= 1'b0;
		state <= IDLE;
	end 
	else case (state)
		// Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
		IDLE: begin 
			if(start) begin
				// Student to add rest of the code  
				h0 <= 32'h6a09e667;
				h1 <= 32'hbb67ae85;
				h2 <= 32'h3c6ef372;
				h3 <= 32'ha54ff53a;
				h4 <= 32'h510e527f;
				h5 <= 32'h9b05688c;
				h6 <= 32'h1f83d9ab;
				h7 <= 32'h5be0cd19;

				a <= 32'h6a09e667;
				b <= 32'hbb67ae85;
				c <= 32'h3c6ef372;
				d <= 32'ha54ff53a;
				e <= 32'h510e527f;
				f <= 32'h9b05688c;
				g <= 32'h1f83d9ab;
				h <= 32'h5be0cd19;

			i <= 1; //loop starts at 1 for i because of optimization of 16bit compute (w[15] becomes new chunk)
			j <= 0; // j used for block state
			n <= 0; // n used as on/off switch
			offset <= 0;
			
			cur_addr <= message_addr;  //current address = where message is located in the memory (input port message_addr)
			cur_we <= 1'b0;				
			cur_write_data <= 0;
			state <= READ;
			end
		end

		READ: begin
			if(offset == 0) begin    
				offset <= offset + 1;
				cur_we <= 1'b0;
				state <= READ;  //recursive function to read all words
			end
			if (offset < NUM_OF_WORDS + 1) begin
				message[offset-1] = mem_read_data;
				offset <= offset + 1;
				cur_we <= 1'b0;
				state <= READ;
			end	
			else begin
				offset <= 16'b0;  //Have finished reading all words and can move to block state
				state <= BLOCK;
			end
	 end

		// SHA-256 FSM 
		// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
		// and write back hash value back to memory
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
		if (j == 0) begin  //Start with 1st message blocks 512 bits
			for (int m = 0; m < 16; m ++) begin
				w[m] = message[m];	// 1st message block (512 bits) sent to compute state
			end
			j <= j + 1;
			state <= COMPUTE;
		end
		if (!(j == num_blocks)) begin
			if (j + 1 == num_blocks ) begin // Start of 2nd message block
				for (int m = 0; m < 4; m ++) begin // 640 minus 512 (from first block) is 128. 128 bits = 4 words
					w[m] <= message[16 + m];  // insert last remaining word from message into 2nd block
					w[3] <= nonce;
				end
				w[4] = 32'h80000000; // Number 1 to start initial padding of 2nd block
				for (int m = 5; m < 15; m ++) begin // Pad the rest of the 319 bits all of bit '0'
					w[m] <= 0;
				end
				w[15] <= 20*32; //32'd640;
				a <= h0;		//At beginning of processing each Mj, initialize a - h as h0 - h7
				b <= h1;
				c <= h2;
				d <= h3;
				e <= h4;
				f <= h5;
				g <= h6;
				h <= h7;

				j <= j + 1;
				state <= COMPUTE;			
			end
		
		end 
	   if (j == num_blocks) begin // When j is 2 (the total number of message blocks), we can move to write state because block completed
			state <= WRITE;
		end	
	end

		// For each block compute hash function
		// Go back to BLOCK stage after each block hash computation is completed and if
		// there are still number of message blocks available in memory otherwise
		// move to WRITE stage
		COMPUTE: begin

	// 64 processing rounds steps for 512-bit block
		if(i <= 64) begin //i starts at 1
			if(i < 17) begin //first 16 bits =  Wt = t'th 32-bit 
				{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i-1], i-1);
				i <= i + 1;
				state <= COMPUTE;
			end
			else if(i == 17 && n==0) begin
					for(int u=0;u<15;u++) begin
						w[u] <= w[u+1]; //makes new w array for new wtnew()
					end
					w[15] <= wtnew(); //adding wtnew to w[15]. The new w we are generating
					n <= 1;
					state <= COMPUTE;
				end
			else begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i-1);
					for(int u=0;u<15;u++) begin
						w[u] <= w[u+1];
					end
					w[15] <= wtnew();
					i <= i + 1;
					n<=0;
					state <= COMPUTE;
				end
			end
			// end of 64 processing rounds
			else begin // first block hash values
				if (j == 0) begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					h4 <= h4 + e;
					h5 <= h5 + f;
					h6 <= h6 + g;
					h7 <= h7 + h;
				end
				else begin // second block has values
					sh0 <= h0 + a;
					sh1 <= h1 + b;
					sh2 <= h2 + c;
					sh3 <= h3 + d;
					sh4 <= h4 + e;
					sh5 <= h5 + f;
					sh6 <= h6 + g;
					sh7 <= h7 + h;
				end

				i <= 0;

				state <= BLOCK;
			end
		end

		// h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
		// h0 to h7 after compute stage has final computed hash value
		// write back these h0 to h7 to memory starting from output_addr
		WRITE: begin
			offset <= 0;
			if (i == 0) begin
				hout[nonce][0] <= sh0;
				i <= i + 1;
			end
			else if (i == 1) begin
				hout[nonce][1] <= sh1;
				i <= i + 1;
			end
			else if (i == 2) begin
				hout[nonce][2] <= sh2;
				i <= i + 1;
			end
			else if (i == 3) begin
				hout[nonce][3] <= sh3;
				i <= i + 1;
			end
			else if (i == 4) begin
				hout[nonce][4] <= sh4;
				i <= i + 1;
			end
			else if (i == 5) begin
				hout[nonce][5] <= sh5;
				i <= i + 1;
			end
			else if (i == 6) begin
				hout[nonce][6] <= sh6;
				i <= i + 1;
			end
			else if (i == 7) begin
				hout[nonce][7] <= sh7;
				i <= i + 1;
			end
			else begin
				i <= 0;
				offset <= 0;
				cur_addr <= 0;
				
				// do other nuance values
				if (nonce < 16) begin
					j <= 1;
					nonce <= nonce + 1;
					state <= BLOCK;
				end
				
				// done all nonce values
				else begin
					state <= IDLE;
				end
			end
		end
	endcase
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule