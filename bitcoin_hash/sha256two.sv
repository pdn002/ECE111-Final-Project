module sha256two #(parameter integer NUM_OF_WORDS = 4)(
 input logic  clk, reset_n, start,
 input logic  [31:0] h0, h1, h2, h3, h4, h5, h6, h7,
 input logic [32:0] w0, w1, w2, w3,
 output logic done, mem_clk,
 output logic [31:0] hout [16][8]
);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE, DONE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[16];
logic [31:0] message[20];
// logic [31:0] wt; // not used
logic [31:0] sh0, sh1, sh2, sh3, sh4, sh5, sh6, sh7;
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j, n; // used as index for making case statements mimick for loop functionality
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [4:0] nonce;
// logic [512:0] memory_block; // not used
// logic [ 7:0] tstep; // not used


// SHA256 K constants  1 column x 64 rows
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
assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

	logic [31:0] totalLength, numBlocks, remainder;
	totalLength = size * 32;
	numBlocks = totalLength / 512;
	remainder = totalLength % 512;
	
	if ( remainder == 0 )
		determine_num_blocks = numBlocks;
	else
		determine_num_blocks = numBlocks + 1;
	
endfunction

function logic [31:0] wtnew; // W[n] word expansion array seen in discussion
	logic [31:0] s1, s0; // internal signals
	begin
		s0 = rightrotate(w[1],7) ^ rightrotate(w[1],18) ^ (w[1] >> 3);
		s1 = rightrotate(w[14],17) ^ rightrotate(w[14],19) ^ (w[14] >> 10);
		wtnew = w[0] + s0 + w[9] + s1;
	end
endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
	 logic [31:0] temp1, temp2;
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25); //sha256 seen in slides and lecture
    ch = (e & f) ^ ((~e) & g);
	 t1 = h + S1 + ch + k[t] + w;
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    sha256_op = {t1+t2, a, b, c, d+t1, e, f, g};
end
endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;


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


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
	 
       if(start) begin
       // Student to add rest of the code. Initialize all values seen in project slides
			a <= h0;
			b <= h1; 
			c <= h2; 
			d <= h3;
			e <= h4; 
			f <= h5; 
			g <= h6; 
			h <= h7;
			i <= 1; //loop starts at 1 for i because of optimization of 16bit compute (w[15] becomes new chunk)
			n <= 0; // n used as on/off switch
			offset <= 0;
			nonce <= 0;	
			state <= READ;
       end
    end
	 
	 // Read 640 bits message from testbench memory in chunks of 32bit words
	 // ie 20 locations from memory by incrementing address offset
	 // move to Block state
	 READ: begin
			message[0] <= w0;
			message[1] <= w1;
			message[2] <= w2;
			message[3] <= w3;
	 end

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
		for (int m = 0; m < 3; m++) begin
			w[m] <= message[m];	// 1st message block (512 bits) sent to compute state
		end
		w[3] <= nonce;
		w[4] = 32'h80000000; // Number 1 to start initial padding of 2nd block
		for (int m = 5; m < 15; m ++) begin // Pad the rest of the 319 bits all of bit '0'
			w[m] = 0;
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

		state <= COMPUTE;			
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
		else begin
			sh0 <= a + h0;
			sh1 <= b + h1;
			sh2 <= c + h2;
			sh3 <= d + h3;
			sh4 <= e + h4;
			sh5 <= f + h5;
			sh6 <= g + h6;
			sh7 <= h + h7;
				
			i <= 1;
			n <= 0;
			state <= WRITE;
		end
	end
    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin	
		if (i < 8) begin
			// Only one hash value is written per clock cycle ( offset < 8)
			case(i)
				0: hout[nonce][0] <= sh0;
				1: hout[nonce][1] <= sh1;
				2: hout[nonce][2] <= sh2;
				3: hout[nonce][3] <= sh3;
				4: hout[nonce][4] <= sh4;
				5: hout[nonce][5] <= sh5;
				6: hout[nonce][6] <= sh6;
				7: hout[nonce][7] <= sh7;
				default: state <= IDLE;
			endcase
			i <= i + 1;
			state <= WRITE;
		end
		else begin
			i <= 0;
			if (nonce < 16) begin
				nonce <= nonce + 1;
				state <= BLOCK;
			end
			else begin
				state <= DONE;
			end
		end
		DONE: begin
		
		end
	end
 endcase
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == DONE);

endmodule
