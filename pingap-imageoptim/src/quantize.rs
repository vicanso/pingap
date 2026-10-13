// Copyright 2024-2025 Tree xie.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Reduces the colours of an image to a palette of 256 at most.
//!
//! The palette is NeuQuant's, from `color_quant`: a net of as many neurons
//! as there are to be colours, trained on the colours of the image. What is
//! here is what the net is trained on and what is made of it:
//!
//! - the colours are counted and premultiplied by their alpha, and an
//!   image that has no more of them than a palette holds keeps them as
//!   they are, without a net;
//! - the entries of a palette are moved to the mean of the colours they
//!   are the entries of, and a colour no neuron is near is given an entry
//!   to itself;
//! - the palette is the smallest one whose error is within what the
//!   quality allows;
//! - the pixels are given their entries with the error of each carried on
//!   to its neighbours, and a pixel that is not seen stays that.
//!
//! Nothing in here may panic on an image, whatever it is: a release build
//! ends on a panic, and the images are what an upstream sends.

use color_quant::NeuQuant;
use rgb::RGBA8;
use std::collections::HashMap;

/// The quality at which the palette is never made smaller than it has to
/// be.
const MAX_QUALITY: u8 = 100;
/// The most colours of a palette.
const MAX_COLORS: usize = 256;
/// The sizes that are tried below it. NeuQuant is made for 256 neurons:
/// its documentation asks for 64 or more, its code says it is not tuned
/// for fewer than 26. The smallest net here is one of 32, less one where
/// an entry is kept for what is not seen, and like every other it is only
/// taken when its error has been measured and is within the limit.
const SMALLER_PALETTES: &[usize] = &[128, 64, 32];
/// How much of the error of a pixel is carried on to its neighbours, in
/// quarters. All of it, as Floyd and Steinberg have it, turns the smooth
/// parts of an image into grain that costs a tenth to a third more bytes;
/// three quarters keep a gradient from breaking into bands as well.
const CARRIED_QUARTERS: i32 = 3;
/// The most that is carried to a pixel, a channel. Next to a part of the
/// image the palette has little for, more than this comes together, and a
/// pixel whose own colour has an entry is given one that is far from it.
const MAX_CARRIED: i32 = 24;
/// How much more than the error of the image the error of one colour of it
/// may be: twenty times as far from its entry, and this is the square of
/// that. The mean alone lets a palette drop what only a few pixels have -
/// one red mark on a page of black and white costs next to nothing there -
/// and what a few pixels have is often what the image is about.
const WORST_COLOR: f64 = 400.0;
/// The colour of a pixel that is not seen.
const CLEAR: [u8; 4] = [0; 4];
/// One entry in this many may be taken from a net for a colour of the
/// image that none of its neurons is near, see [`Palette::pin`].
const PINNED_SHARE: usize = 16;

/// The most pixels the sample of an image has: what a net is trained on,
/// whatever the size of the image.
const SAMPLE_PIXELS: u64 = 65_536;
/// The fewest: a smaller image is gone through as often as it takes. A net
/// that has seen each pixel of an icon once has not learnt them, and is
/// several decibels worse for it.
const MIN_SAMPLE: u64 = 16_384;
/// NeuQuant learns from one pixel in this many. The sample is small and
/// every pixel of it is there for a reason.
const SAMPLE_FACTOR: i32 = 1;

/// The most colours that are told apart. An image with more of them has
/// those put together that share the upper bits of every channel, by one
/// entry of [`SHIFTS`] after the other.
const MAX_GROUPS: usize = 32_768;
// `shares` gives every group a pixel of the sample before anything else.
const _: () = assert!(MAX_GROUPS as u64 <= SAMPLE_PIXELS);
/// The lower bits of a channel that are left out of what tells two colours
/// apart. The last one leaves three bits a channel, 4096 groups at most.
const SHIFTS: [u32; 5] = [0, 2, 3, 4, 5];

/// The pixels of one colour, or of the colours that are put together.
#[derive(Clone, Copy, Default)]
struct Group {
    /// The number of pixels.
    count: u64,
    /// The sum of each channel,
    sum: [u64; 4],
    /// and the sum of the squares of all four.
    squares: u64,
}

impl Group {
    fn add(&mut self, color: RGBA8, count: u64) {
        self.count += count;
        let channels = [color.r, color.g, color.b, color.a];
        for (sum, value) in self.sum.iter_mut().zip(channels) {
            let value = u64::from(value);
            *sum += count * value;
            self.squares += count * value * value;
        }
    }
    fn merge(&mut self, other: &Group) {
        self.count += other.count;
        for (sum, value) in self.sum.iter_mut().zip(other.sum) {
            *sum += value;
        }
        self.squares += other.squares;
    }
    /// The mean of the pixels.
    fn color(&self) -> [u8; 4] {
        self.sum
            .map(|sum| ((sum + self.count / 2) / self.count) as u8)
    }
    /// The squared distance of the pixels from their mean, summed. In
    /// whole numbers up to the division: for one colour it is nothing, not
    /// what is left of two large numbers taken from each other.
    fn scatter(&self) -> f64 {
        let count = u128::from(self.count);
        let squares = u128::from(self.squares) * count;
        let mean: u128 = self
            .sum
            .iter()
            .map(|sum| u128::from(*sum) * u128::from(*sum))
            .sum();
        squares.saturating_sub(mean) as f64 / self.count as f64
    }
}

/// The colours of an image, counted.
///
/// The map is the standard one with its random keys on purpose: the colours
/// are whatever an upstream sends, and with a hash that can be predicted an
/// image could be made of colours that all meet in one slot.
struct Groups {
    map: HashMap<u32, Group>,
    /// The entry of [`SHIFTS`] the colours are told apart by.
    level: usize,
}

impl Groups {
    /// The bits of a colour that tell it apart from the others.
    fn mask(&self) -> u32 {
        let channel = 0xff_u8 << SHIFTS[self.level];
        u32::from_le_bytes([channel; 4])
    }
    fn add(&mut self, color: RGBA8, count: u64) {
        let channels = [color.r, color.g, color.b, color.a];
        let key = u32::from_le_bytes(channels) & self.mask();
        self.map.entry(key).or_default().add(color, count);
        while self.map.len() > MAX_GROUPS && self.level + 1 < SHIFTS.len() {
            self.level += 1;
            let mask = self.mask();
            let mut map: HashMap<u32, Group> = HashMap::new();
            for (key, group) in self.map.iter() {
                map.entry(key & mask).or_default().merge(group);
            }
            self.map = map;
        }
    }
    /// The groups, in an order that is the same for the same image: what
    /// comes out for an image must not depend on the keys of the map.
    fn into_sorted(self) -> Vec<Group> {
        let mut groups: Vec<(u32, Group)> = self.map.into_iter().collect();
        groups.sort_unstable_by_key(|(key, _)| *key);
        groups.into_iter().map(|(_, group)| group).collect()
    }
}

/// The colours of an image as they were counted.
struct Counted {
    groups: Vec<Group>,
    /// The bits of a colour that tell it apart from the others: all of
    /// them when every colour has a group of its own.
    mask: u32,
    /// Whether a pixel of the image is not seen at all.
    clear: bool,
}

/// Counts the colours of `pixels`, which are premultiplied.
fn count_colors(pixels: &[RGBA8]) -> Counted {
    let mut groups = Groups {
        map: HashMap::new(),
        level: 0,
    };
    let mut clear = false;
    // Pixels next to each other are of one colour more often than not.
    let mut run: Option<(RGBA8, u64)> = None;
    for pixel in pixels {
        match run.as_mut() {
            Some((color, count)) if *color == *pixel => *count += 1,
            _ => {
                clear |= pixel.a == 0;
                if let Some((color, count)) = run.replace((*pixel, 1)) {
                    groups.add(color, count);
                }
            },
        }
    }
    if let Some((color, count)) = run {
        groups.add(color, count);
    }
    Counted {
        mask: groups.mask(),
        groups: groups.into_sorted(),
        clear,
    }
}

/// How often each group is in the sample. An image of a size the sample
/// may have is its own sample. Of a larger one, and of a smaller one, each
/// group has its share of [`SAMPLE_PIXELS`] or of [`MIN_SAMPLE`], what is
/// left after rounding down going to the largest remainders. With `every`
/// each group is in it once before anything is shared, so that a colour
/// of a few pixels is still one the net is trained on.
fn shares(counts: &[u64], every: bool) -> Vec<u64> {
    let total: u64 = counts.iter().sum();
    if total == 0 || (MIN_SAMPLE..=SAMPLE_PIXELS).contains(&total) {
        return counts.to_vec();
    }
    let sample = total.clamp(MIN_SAMPLE, SAMPLE_PIXELS);
    let base = u64::from(every);
    let budget = sample.saturating_sub(base * counts.len() as u64);
    let mut shares = Vec::with_capacity(counts.len());
    let mut remainders = Vec::with_capacity(counts.len());
    let mut given = 0;
    for (index, count) in counts.iter().enumerate() {
        let part = u128::from(*count) * u128::from(budget);
        let whole = (part / u128::from(total)) as u64;
        remainders.push(((part % u128::from(total)) as u64, index));
        shares.push(base + whole);
        given += whole;
    }
    remainders.sort_unstable_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let left = budget.saturating_sub(given) as usize;
    for (_, index) in remainders.into_iter().take(left) {
        shares[index] += 1;
    }
    shares
}

/// What a palette is worked out from, and what its error is measured on.
struct Sample {
    /// The colour of each group,
    colors: Vec<[u8; 4]>,
    /// and the number of pixels it stands for.
    counts: Vec<u64>,
    /// The squared distance of the pixels from the colour of their group,
    /// summed: the part of the error that is the same for every palette.
    scatter: f64,
    /// The colours once more, each as often as its share, `SAMPLE_PIXELS`
    /// at most: what a net is trained on.
    pixels: Vec<[u8; 4]>,
    /// Whether a pixel of the image is not seen at all.
    clear: bool,
    /// The bits of a colour that tell it apart from the others: all of
    /// them when every colour of the image is one of `colors`.
    mask: u32,
    /// Whether the colours of the image are no more than a palette holds,
    /// each of them as it is.
    fits: bool,
}

impl Sample {
    fn new(pixels: &[RGBA8]) -> Self {
        let Counted {
            groups,
            mask,
            clear,
        } = count_colors(pixels);
        let exact = mask == u32::MAX;
        let counts: Vec<u64> = groups.iter().map(|group| group.count).collect();
        let colors: Vec<[u8; 4]> = groups.iter().map(Group::color).collect();
        let pixels = colors
            .iter()
            .zip(shares(&counts, exact))
            .flat_map(|(color, share)| {
                std::iter::repeat_n(*color, share as usize)
            })
            .collect();
        Sample {
            scatter: groups.iter().map(Group::scatter).sum(),
            fits: exact && colors.len() <= MAX_COLORS,
            colors,
            counts,
            pixels,
            clear,
            mask,
        }
    }
    /// The error of the image with every group given the entry of the
    /// palette that is nearest to its colour.
    fn error(&self, palette: &Palette) -> PaletteError {
        let mut sum = self.scatter;
        let mut pixels = 0u64;
        let mut worst = 0f64;
        for (color, count) in self.colors.iter().zip(&self.counts) {
            let to = palette.colors[usize::from(palette.entry_of(color))];
            let distance = distance(color, &to);
            sum += distance * *count as f64;
            pixels += count;
            worst = worst.max(distance);
        }
        PaletteError {
            mean: sum / pixels.max(1) as f64 / 4.0,
            worst: worst / 4.0,
        }
    }
}

/// How far a palette is from an image: the squared error, a channel,
struct PaletteError {
    /// of all the pixels, as their mean,
    mean: f64,
    /// and of the colour that is furthest from its entry.
    worst: f64,
}

impl PaletteError {
    /// Whether a palette with this error will do where the mean may be
    /// `limit`.
    fn within(&self, limit: f64) -> bool {
        self.mean <= limit && self.worst <= limit * WORST_COLOR
    }
}

/// The mean error a palette may have at a quality, as [`Sample::error`]
/// measures it: a peak signal-to-noise ratio of 30 dB at 0, 44 dB at 90.
fn error_limit(quality: u8) -> f64 {
    let psnr = 30.0 + f64::from(quality) * 14.0 / 90.0;
    255.0 * 255.0 / 10f64.powf(psnr / 10.0)
}

/// What finds the entry of a palette for a colour.
enum Search {
    /// The colours of the image are the palette.
    Exact(HashMap<[u8; 4], u8>),
    /// A net, and the entry each of its neurons has in the palette.
    Net(Box<NeuQuant>, Vec<u8>),
}

/// The colours of a palette, premultiplied, in the order they are written.
struct Palette {
    colors: Vec<[u8; 4]>,
    /// The entry for what is not seen, where the image has such pixels.
    clear: Option<u8>,
    /// The colours that have an entry to themselves, by the bits `mask`
    /// leaves of them, see [`Palette::pin`].
    pinned: HashMap<u32, u8>,
    mask: u32,
    search: Search,
}

impl Palette {
    /// The colours of the sample as they are.
    fn exact(sample: &Sample) -> Self {
        let mut colors = sample.colors.clone();
        // The ones that are not opaque first: the list of alphas a png
        // has ends with the last of them.
        colors.sort_unstable_by_key(|color| (color[3], *color));
        let index = colors
            .iter()
            .enumerate()
            .map(|(at, color)| (*color, at as u8))
            .collect();
        Palette {
            clear: clear_entry(&colors, sample),
            colors,
            pinned: HashMap::new(),
            mask: sample.mask,
            search: Search::Exact(index),
        }
    }
    /// A net of `size` neurons trained on the sample, every colour of it
    /// then moved to the mean of the colours the net gives it. An image
    /// with pixels that are not seen has an entry that is clear, one more
    /// than the net where none of its neurons is.
    fn trained(sample: &Sample, size: usize, far: f64) -> Self {
        // never more neurons than leave room for the clear entry
        let size = size.min(MAX_COLORS - usize::from(sample.clear));
        let net =
            NeuQuant::new(SAMPLE_FACTOR, size, sample.pixels.as_flattened());
        let neurons: Vec<[u8; 4]> =
            (0..size).filter_map(|at| net.lookup(at)).collect();
        let mut order: Vec<usize> = (0..neurons.len()).collect();
        order.sort_by_key(|at| (neurons[*at][3], *at));
        let mut colors = Vec::with_capacity(neurons.len() + 1);
        if sample.clear && !neurons.contains(&CLEAR) {
            colors.push(CLEAR);
        }
        let mut entries = vec![0u8; neurons.len()];
        for at in order {
            entries[at] = colors.len() as u8;
            colors.push(neurons[at]);
        }
        let mut palette = Palette {
            clear: clear_entry(&colors, sample),
            colors,
            pinned: HashMap::new(),
            mask: sample.mask,
            search: Search::Net(Box::new(net), entries),
        };
        let used = palette.settle(sample);
        palette.pin(sample, used, far);
        palette
    }
    /// The entry a colour has to itself, if it has one.
    fn pinned_entry(&self, color: &[u8; 4]) -> Option<u8> {
        if self.pinned.is_empty() {
            return None;
        }
        self.pinned
            .get(&(u32::from_le_bytes(*color) & self.mask))
            .copied()
    }
    /// Whether colours other than its own are looked up in it: the error
    /// of a pixel is then carried on to its neighbours.
    fn dithered(&self) -> bool {
        matches!(self.search, Search::Net(..))
    }
    /// The entry nearest to a colour.
    fn entry_of(&self, color: &[u8; 4]) -> u8 {
        if let (&CLEAR, Some(clear)) = (color, self.clear) {
            return clear;
        }
        if let Some(entry) = self.pinned_entry(color) {
            return entry;
        }
        match &self.search {
            Search::Exact(index) => index.get(color).copied().unwrap_or(0),
            Search::Net(net, entries) => {
                entries.get(net.index_of(color)).copied().unwrap_or(0)
            },
        }
    }
    /// Moves every entry to the mean of the colours of the sample it is
    /// the entry of. A neuron is where the training left it, which is
    /// near that mean and seldom on it: a flat area of one colour comes
    /// out one step off, and the error of it carried on as scattered
    /// pixels of the next colour.
    ///
    /// Returns the number of pixels each entry is the entry of.
    fn settle(&mut self, sample: &Sample) -> Vec<u64> {
        let mut sums = vec![[0u64; 4]; self.colors.len()];
        let mut counts = vec![0u64; self.colors.len()];
        for (color, count) in sample.colors.iter().zip(&sample.counts) {
            let entry = usize::from(self.entry_of(color));
            counts[entry] += count;
            for (sum, value) in sums[entry].iter_mut().zip(color) {
                *sum += u64::from(*value) * count;
            }
        }
        let clear = self.clear.map(usize::from);
        let entries = self.colors.iter_mut().zip(sums).zip(&counts);
        for (at, ((color, sum), count)) in entries.enumerate() {
            if *count > 0 && Some(at) != clear {
                *color = sum.map(|sum| ((sum + count / 2) / *count) as u8);
            }
        }
        counts
    }
    /// The colours of the sample that are further than `far` (a squared
    /// distance) from their entry, with what the image gains by each
    /// having an entry to itself: that distance for every pixel of it.
    /// The ones that gain most first, and no more of them than the
    /// palette gives entries to.
    fn far_colors(&self, sample: &Sample, far: f64) -> Vec<(f64, [u8; 4])> {
        let mut colors: Vec<(f64, [u8; 4])> = sample
            .colors
            .iter()
            .zip(&sample.counts)
            .filter(|(color, _)| **color != CLEAR)
            .filter_map(|(color, count)| {
                let to = self.colors[usize::from(self.entry_of(color))];
                let distance = distance(color, &to);
                (distance > far).then_some((distance * *count as f64, *color))
            })
            .collect();
        colors.sort_unstable_by(|a, b| b.0.total_cmp(&a.0).then(b.1.cmp(&a.1)));
        colors.truncate(self.colors.len() / PINNED_SHARE);
        colors
    }
    /// The entry of `free` whose pixels lose least by going to the entry
    /// of `free` nearest to it, `used` being the pixels of each: what they
    /// lose, the entry, and the one they would go to.
    fn cheapest(
        &self,
        free: &[usize],
        used: &[u64],
    ) -> Option<(f64, usize, usize)> {
        let cost = |at: &usize| {
            let (distance, to) = free
                .iter()
                .filter(|to| *to != at)
                .map(|to| (distance(&self.colors[*at], &self.colors[*to]), *to))
                .min_by(|a, b| a.0.total_cmp(&b.0))?;
            let pixels = used.get(*at).copied().unwrap_or(u64::MAX);
            Some((distance * pixels as f64, *at, to))
        };
        free.iter()
            .filter_map(cost)
            .min_by(|a, b| a.0.total_cmp(&b.0).then(a.1.cmp(&b.1)))
    }
    /// Gives the colours that are further than `far` from their entry an
    /// entry to themselves, where the image gains more by it than it
    /// loses: the entry is taken from the pixels that lose least by going
    /// to the entry nearest to theirs, `used` being the pixels of each.
    ///
    /// A net is a map of where most of the colours are. What a few pixels
    /// have and nothing else is near - the mark on a chart, the pin on a
    /// map - has no neuron, and comes out as the nearest colour that has
    /// one. The entry it is given is as a rule one that two neurons share
    /// or that no pixel has; it must not be the only one of another small
    /// part of the image, whose pixels would go to wherever is nearest.
    fn pin(&mut self, sample: &Sample, mut used: Vec<u64>, far: f64) {
        let clear = self.clear.map(usize::from);
        // the entries that can be given up, or be gone to
        let mut free: Vec<usize> = (0..self.colors.len())
            .filter(|at| Some(*at) != clear)
            .collect();
        for (gain, color) in self.far_colors(sample, far) {
            let Some((cost, at, to)) = self.cheapest(&free, &used) else {
                return;
            };
            if cost >= gain {
                continue;
            }
            self.redirect(at, to);
            if let Some(pixels) = used.get(at).copied() {
                used[to] += pixels;
            }
            free.retain(|entry| *entry != at);
            self.colors[at] = color;
            let key = u32::from_le_bytes(color) & self.mask;
            self.pinned.insert(key, at as u8);
        }
    }
    /// Sends what the net gives the entry `from` to the entry `to`.
    fn redirect(&mut self, from: usize, to: usize) {
        let Search::Net(_, entries) = &mut self.search else {
            return;
        };
        for entry in entries.iter_mut() {
            if usize::from(*entry) == from {
                *entry = to as u8;
            }
        }
    }
}

/// The squared distance of two colours.
fn distance(a: &[u8; 4], b: &[u8; 4]) -> f64 {
    a.iter()
        .zip(b)
        .map(|(a, b)| (f64::from(*a) - f64::from(*b)).powi(2))
        .sum()
}

/// The entry of `colors` for the pixels that are not seen, for a sample
/// that has any.
fn clear_entry(colors: &[[u8; 4]], sample: &Sample) -> Option<u8> {
    let clear = colors.iter().position(|color| *color == CLEAR)?;
    sample.clear.then_some(clear as u8)
}

/// The palette for the image the sample is of.
///
/// Its own colours where they fit, whatever the quality: nothing is lost
/// by them and nothing is carried on, and a net of fewer colours with its
/// grain is more often the larger file than the smaller one.
///
/// Else a net of 256, and of half as many as often as the error stays
/// within what the quality allows. One of 256 is the best there is,
/// whatever its error. An image with pixels that are not seen gets one
/// neuron less, which leaves room for the clear entry.
fn choose_palette(sample: &Sample, quality: u8) -> Palette {
    if sample.fits {
        return Palette::exact(sample);
    }
    let limit = error_limit(quality);
    // what `PaletteError::within` allows the worst colour, as a distance
    let far = limit * WORST_COLOR * 4.0;
    let reserved = usize::from(sample.clear);
    let mut best = Palette::trained(sample, MAX_COLORS - reserved, far);
    if quality >= MAX_QUALITY || !sample.error(&best).within(limit) {
        return best;
    }
    for size in SMALLER_PALETTES {
        let smaller = Palette::trained(sample, size - reserved, far);
        if !sample.error(&smaller).within(limit) {
            break;
        }
        best = smaller;
    }
    best
}

/// The error that has come to the pixels of a row and of the one below
/// it, in sixty-fourths, with one more at each end so that no edge is a
/// case of its own.
struct Carried {
    ahead: Vec<[i32; 4]>,
    below: Vec<[i32; 4]>,
}

impl Carried {
    fn new(width: usize) -> Self {
        Carried {
            ahead: vec![[0; 4]; width + 2],
            below: vec![[0; 4]; width + 2],
        }
    }
    /// The colour to find an entry for: that of the pixel at `x` and what
    /// has been carried to it.
    fn wanted(&self, x: usize, pixel: [u8; 4]) -> [u8; 4] {
        let mut wanted = pixel;
        for (value, carried) in wanted.iter_mut().zip(self.ahead[x + 1]) {
            let carried = (carried + 32).div_euclid(64);
            let sum =
                i32::from(*value) + carried.clamp(-MAX_CARRIED, MAX_CARRIED);
            *value = sum.clamp(0, 255) as u8;
        }
        wanted
    }
    /// Carries what the pixel at `x` wanted and did not get on to the
    /// pixels after it and below it, in Floyd and Steinberg's shares.
    fn spread(
        &mut self,
        x: usize,
        backwards: bool,
        wanted: [u8; 4],
        got: [u8; 4],
    ) {
        let (next, last) = if backwards { (x, x + 2) } else { (x + 2, x) };
        for (channel, (wanted, got)) in wanted.into_iter().zip(got).enumerate()
        {
            let error = (i32::from(wanted) - i32::from(got)) * CARRIED_QUARTERS;
            self.ahead[next][channel] += error * 7;
            self.below[last][channel] += error * 3;
            self.below[x + 1][channel] += error * 5;
            self.below[next][channel] += error;
        }
    }
    fn next_row(&mut self) {
        std::mem::swap(&mut self.ahead, &mut self.below);
        self.below.fill([0; 4]);
    }
}

/// Gives every pixel the entry of its own colour, for a palette that has
/// them all.
fn remap_exact(pixels: &[RGBA8], palette: &Palette) -> Vec<u8> {
    // Pixels next to each other are of one colour more often than not.
    let mut last: Option<(RGBA8, u8)> = None;
    pixels
        .iter()
        .map(|pixel| match last {
            Some((color, entry)) if color == *pixel => entry,
            _ => {
                let entry =
                    palette.entry_of(&[pixel.r, pixel.g, pixel.b, pixel.a]);
                last = Some((*pixel, entry));
                entry
            },
        })
        .collect()
}

/// Gives every pixel the entry nearest to its colour and to what the
/// pixels before it did not get: the error of each is carried on, every
/// other row from right to left. A pixel that is not seen takes the clear
/// entry, one whose colour has an entry to itself takes that, and neither
/// takes what was carried to it nor leaves an error.
///
/// It is done here and not by `image::imageops::dither`, which reaches
/// beyond an image that is one pixel wide.
fn remap_dithered(
    pixels: &[RGBA8],
    width: usize,
    palette: &Palette,
) -> Vec<u8> {
    let mut entries = vec![0u8; pixels.len()];
    let mut carried = Carried::new(width);
    let rows = pixels
        .chunks_exact(width)
        .zip(entries.chunks_exact_mut(width));
    for (y, (row, out)) in rows.enumerate() {
        let backwards = y % 2 == 1;
        for step in 0..width {
            let x = if backwards { width - 1 - step } else { step };
            let pixel = [row[x].r, row[x].g, row[x].b, row[x].a];
            if let (CLEAR, Some(clear)) = (pixel, palette.clear) {
                out[x] = clear;
                continue;
            }
            if let Some(entry) = palette.pinned_entry(&pixel) {
                out[x] = entry;
                continue;
            }
            let wanted = carried.wanted(x, pixel);
            out[x] = palette.entry_of(&wanted);
            let got = palette.colors[usize::from(out[x])];
            carried.spread(x, backwards, wanted, got);
        }
        carried.next_row();
    }
    entries
}

/// Multiplies the colour of every pixel by its alpha. A pixel that is not
/// seen has no colour afterwards, and one that is seen faintly differs
/// from its neighbours by as little as it shows.
fn premultiply(pixels: &mut [RGBA8]) {
    for pixel in pixels.iter_mut().filter(|pixel| pixel.a != u8::MAX) {
        let alpha = u32::from(pixel.a);
        let scale = |value: u8| ((u32::from(value) * alpha + 127) / 255) as u8;
        *pixel =
            RGBA8::new(scale(pixel.r), scale(pixel.g), scale(pixel.b), pixel.a);
    }
}

/// The colour a premultiplied one stands for.
fn straight(color: &[u8; 4]) -> RGBA8 {
    let [r, g, b, a] = *color;
    if a == 0 {
        return RGBA8::new(0, 0, 0, 0);
    }
    let alpha = u32::from(a);
    let scale = |value: u8| {
        ((u32::from(value) * 255 + alpha / 2) / alpha).min(255) as u8
    };
    RGBA8::new(scale(r), scale(g), scale(b), a)
}

/// Reduces `pixels`, `width` of them to a row, to a palette and an entry of
/// it for each pixel. `quality` is 0 to 100: at 100 the palette has as many
/// colours as it can, below that as few as keep the error within what the
/// quality allows. None when the size is not the number of pixels.
///
/// The pixels are left premultiplied.
pub(crate) fn quantize(
    pixels: &mut [RGBA8],
    width: usize,
    height: usize,
    quality: u8,
) -> Option<(Vec<RGBA8>, Vec<u8>)> {
    if pixels.is_empty() || width.checked_mul(height) != Some(pixels.len()) {
        return None;
    }
    premultiply(pixels);
    let palette = choose_palette(&Sample::new(pixels), quality);
    let entries = if palette.dithered() {
        remap_dithered(pixels, width, &palette)
    } else {
        remap_exact(pixels, &palette)
    };
    Some((palette.colors.iter().map(straight).collect(), entries))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// Numbers that are the same on every run.
    struct Noise(u64);

    impl Noise {
        fn next(&mut self) -> u8 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 >> 24) as u8
        }
        fn pixels(&mut self, count: usize, opaque: bool) -> Vec<RGBA8> {
            (0..count)
                .map(|_| {
                    let alpha = if opaque { 255 } else { self.next() };
                    RGBA8::new(self.next(), self.next(), self.next(), alpha)
                })
                .collect()
        }
    }

    /// Rows that go from one colour to another in more steps than a
    /// palette has colours.
    fn ramp(width: usize, height: usize) -> Vec<RGBA8> {
        (0..width * height)
            .map(|at| {
                let x = at % width;
                RGBA8::new(
                    (x * 256 / width) as u8,
                    (x * 100 / width) as u8,
                    255 - (x * 256 / width) as u8,
                    255,
                )
            })
            .collect()
    }

    /// Colours that change a little from one pixel to the next, many
    /// more of them than a palette holds, and none of them near yellow.
    fn smooth(width: usize, height: usize) -> Vec<RGBA8> {
        (0..width * height)
            .map(|at| {
                let (x, y) = (at % width, at / width);
                RGBA8::new(
                    (x * 255 / width) as u8,
                    (y * 160 / height) as u8,
                    (200 - x * 100 / width + y * 55 / height) as u8,
                    255,
                )
            })
            .collect()
    }

    /// The colours of the entries the pixels were given.
    fn painted(palette: &[RGBA8], entries: &[u8]) -> Vec<RGBA8> {
        entries
            .iter()
            .map(|entry| palette[usize::from(*entry)])
            .collect()
    }

    #[test]
    fn test_sample_is_bounded() {
        // an image of a size the sample may have is its own sample
        assert_eq!(vec![3, 1, 60_000], shares(&[3, 1, 60_000], true));
        assert_eq!(vec![SAMPLE_PIXELS], shares(&[SAMPLE_PIXELS], false));
        assert_eq!(vec![MIN_SAMPLE], shares(&[MIN_SAMPLE], false));
        // a smaller one is gone through as often as it takes
        assert_eq!(vec![12_288, 4_096], shares(&[3, 1], false));
        assert_eq!(vec![12_288, 4_096], shares(&[3, 1], true));
        assert_eq!(vec![MIN_SAMPLE], shares(&[1], true));
        assert_eq!(MIN_SAMPLE, shares(&[7; 289], true).iter().sum::<u64>());
        assert_eq!(vec![0u64; 0], shares(&[], true));

        let mut noise = Noise(7);
        for every in [true, false] {
            for groups in [2, 3, 300, 5_000, MAX_GROUPS] {
                // a few groups with nearly everything, the rest small
                let counts: Vec<u64> = (0..groups)
                    .map(|index| {
                        let small = u64::from(noise.next()) + 1;
                        if index < 2 { small * 500_000 } else { small }
                    })
                    .collect();
                let shares = shares(&counts, every);
                assert_eq!(counts.len(), shares.len());
                // all of the sample is used, and no more
                assert_eq!(SAMPLE_PIXELS, shares.iter().sum::<u64>());
                if every {
                    assert_eq!(true, shares.iter().all(|share| *share >= 1));
                }
                // the larger group never has the smaller share
                let heavy = shares[0].min(shares[1]);
                assert_eq!(true, shares.iter().skip(2).all(|s| *s <= heavy));
            }
        }

        // and so is what a net is trained on, for an image far beyond it
        let sample = Sample::new(&Noise(31).pixels(300_000, false));
        assert_eq!(SAMPLE_PIXELS as usize, sample.pixels.len());
        assert_eq!(false, sample.fits);
    }

    #[test]
    fn test_colours_are_counted() {
        // few colours: each has a group of its own
        let mut pixels = vec![RGBA8::new(1, 2, 3, 255); 1000];
        pixels.extend(vec![RGBA8::new(1, 2, 4, 255); 10]);
        pixels.push(RGBA8::new(0, 0, 0, 0));
        pixels.extend(vec![RGBA8::new(1, 2, 3, 255); 5]);
        let Counted {
            groups,
            mask,
            clear,
        } = count_colors(&pixels);
        assert_eq!((u32::MAX, true), (mask, clear));
        let mut counts: Vec<(u64, [u8; 4])> = groups
            .iter()
            .map(|group| (group.count, group.color()))
            .collect();
        counts.sort_unstable();
        assert_eq!(
            vec![
                (1, [0, 0, 0, 0]),
                (10, [1, 2, 4, 255]),
                (1005, [1, 2, 3, 255])
            ],
            counts
        );
        assert_eq!(0.0, groups.iter().map(Group::scatter).sum::<f64>());

        // more colours than are told apart: put together, every pixel
        // still counted, and what is lost by it is known
        let pixels = Noise(11).pixels(200_000, false);
        let Counted { groups, mask, .. } = count_colors(&pixels);
        // three bits a channel is what four channels of noise come to
        assert_eq!(0xe0e0_e0e0, mask);
        assert_eq!(true, groups.len() <= MAX_GROUPS);
        assert_eq!(
            200_000,
            groups.iter().map(|group| group.count).sum::<u64>()
        );
        assert_eq!(true, groups.iter().map(Group::scatter).sum::<f64>() > 0.0);
        // The colour of a group is one of the group: the groups are in
        // the order of their keys, and so are their colours when all but
        // the bits of a key are left out.
        let keys: Vec<u32> = groups
            .iter()
            .map(|group| u32::from_le_bytes(group.color()) & mask)
            .collect();
        assert_eq!(true, keys.is_sorted_by(|a, b| a < b));

        assert_eq!(0, count_colors(&[]).groups.len());
        let opaque = count_colors(&[RGBA8::new(1, 2, 3, 255); 4]);
        assert_eq!((1, false), (opaque.groups.len(), opaque.clear));
    }

    #[test]
    fn test_alpha_is_multiplied_in_and_out() {
        let mut pixels = vec![
            RGBA8::new(200, 100, 50, 255),
            RGBA8::new(200, 100, 50, 128),
            RGBA8::new(200, 100, 50, 0),
            RGBA8::new(255, 255, 255, 1),
        ];
        premultiply(&mut pixels);
        assert_eq!(
            vec![
                RGBA8::new(200, 100, 50, 255),
                RGBA8::new(100, 50, 25, 128),
                RGBA8::new(0, 0, 0, 0),
                RGBA8::new(1, 1, 1, 1),
            ],
            pixels
        );
        let back: Vec<RGBA8> = pixels
            .iter()
            .map(|pixel| straight(&[pixel.r, pixel.g, pixel.b, pixel.a]))
            .collect();
        assert_eq!(
            vec![
                RGBA8::new(200, 100, 50, 255),
                RGBA8::new(199, 100, 50, 128),
                RGBA8::new(0, 0, 0, 0),
                RGBA8::new(255, 255, 255, 1),
            ],
            back
        );
        // a colour above its alpha, which a neuron may be left at, is
        // held to the most a channel has; one without alpha has no colour
        assert_eq!(RGBA8::new(255, 128, 0, 2), straight(&[3, 1, 0, 2]));
        assert_eq!(RGBA8::new(0, 0, 0, 0), straight(&[3, 1, 0, 0]));
    }

    /// An image of no more colours than a palette holds keeps them, at
    /// every quality.
    #[test]
    fn test_few_colours_are_kept() {
        let mut noise = Noise(3);
        let colors = noise.pixels(200, true);
        let original: Vec<RGBA8> = (0..120_000)
            .map(|_| colors[usize::from(noise.next()) % colors.len()])
            .collect();
        for quality in [100, 90, 1] {
            let mut pixels = original.clone();
            let (palette, entries) =
                quantize(&mut pixels, 400, 300, quality).unwrap();
            assert_eq!(200, palette.len(), "{quality}");
            assert_eq!(true, original == painted(&palette, &entries));
        }

        // Two colours with nearly all the pixels and a few more next to
        // one of them in value: what a quantizer that adds colours up in
        // an `f32` goes wrong on.
        let heavy = [
            (RGBA8::new(200, 23, 115, 255), 954_269),
            (RGBA8::new(145, 108, 62, 255), 584_252),
            (RGBA8::new(75, 135, 134, 255), 35),
            (RGBA8::new(201, 23, 115, 255), 2),
            (RGBA8::new(202, 23, 115, 255), 4),
        ];
        let original: Vec<RGBA8> = heavy
            .iter()
            .flat_map(|(color, count)| std::iter::repeat_n(*color, *count))
            .collect();
        for quality in [100, 90, 1] {
            let mut pixels = original.clone();
            let count = pixels.len();
            let (palette, entries) =
                quantize(&mut pixels, count, 1, quality).unwrap();
            assert_eq!(5, palette.len());
            assert_eq!(true, original == painted(&palette, &entries));
        }
    }

    #[test]
    fn test_quality_sets_the_size_of_the_palette() {
        // colours along a line, a few more of them than a palette holds
        let original = ramp(1024, 50);
        assert_eq!(false, Sample::new(&original).fits);
        let sizes: Vec<usize> = [100, 90, 60, 30, 1]
            .iter()
            .map(|quality| {
                let mut pixels = original.clone();
                quantize(&mut pixels, 1024, 50, *quality).unwrap().0.len()
            })
            .collect();
        assert_eq!(vec![256, 64, 32, 32, 32], sizes);

        // What a quality allows is what a palette that was made smaller
        // is held to.
        let sample = Sample::new(&original);
        for quality in [90, 60, 30, 1] {
            let palette = choose_palette(&sample, quality);
            let error = sample.error(&palette);
            assert_eq!(true, error.within(error_limit(quality)), "{quality}");
            assert_eq!(true, error.mean > 0.0, "{quality}");
        }
        assert_eq!(true, error_limit(90) < error_limit(1));

        // Where 256 colours are not enough for it, they are what there
        // is: the palette is not refused, and not made smaller.
        let sample = Sample::new(&Noise(17).pixels(120_000, true));
        for quality in [100, 90, 1] {
            let palette = choose_palette(&sample, quality);
            assert_eq!(256, palette.colors.len());
            let error = sample.error(&palette);
            assert_eq!(false, error.within(error_limit(quality)), "{quality}");
        }
    }

    /// Regression: a net has no neuron for what a few pixels have and
    /// nothing else is near, and such a colour came out as the nearest
    /// one that had: it gets an entry to itself.
    #[test]
    fn test_colour_of_a_few_pixels_is_kept() {
        // Where the colours are told apart one by one, and where those
        // that share their upper bits are put together.
        let cases = [
            (300, 100, u32::MAX, RGBA8::new(0, 250, 255, 255)),
            (600, 400, 0xfcfc_fcfc, RGBA8::new(10, 200, 20, 255)),
        ];
        for (width, height, mask, mark) in cases {
            let mut original = smooth(width, height);
            let at = width * height / 2 + width / 3;
            original[at..at + 6].fill(mark);

            let sample = Sample::new(&original);
            assert_eq!(mask, sample.mask);
            assert_eq!(false, sample.fits);
            // the net alone has nothing near it
            let alone = Palette::trained(&sample, 256, f64::MAX);
            assert_eq!(true, alone.pinned.is_empty());
            let key = [mark.r, mark.g, mark.b, mark.a];
            let nearest = alone.colors[usize::from(alone.entry_of(&key))];
            assert_eq!(true, distance(&key, &nearest) > 80.0 * 80.0);

            for quality in [100, 90] {
                let mut pixels = original.clone();
                let (palette, entries) =
                    quantize(&mut pixels, width, height, quality).unwrap();
                assert_eq!(true, palette.len() <= 256);
                let result = painted(&palette, &entries);
                assert_eq!(vec![mark; 6], result[at..at + 6], "{quality}");
            }
            // A low quality allows a colour to be as far from its entry
            // as this one is from its neighbours: whether it is kept
            // apart there is left to the net.
        }
    }

    /// The gradient the review's two cases are on, and a block of 24 by
    /// 24 pixels in the middle of it.
    fn gradient_with_block(
        width: usize,
        height: usize,
        block: impl Fn(usize) -> RGBA8,
    ) -> (Vec<RGBA8>, Vec<usize>) {
        let mut pixels: Vec<RGBA8> = (0..width * height)
            .map(|at| {
                let (x, y) = (at % width, at / width);
                RGBA8::new(
                    (60 + x * 190 / width) as u8,
                    (80 + y * 170 / height) as u8,
                    (250 - x * 100 / width - y * 50 / height) as u8,
                    255,
                )
            })
            .collect();
        let mut inside = Vec::new();
        for y in 0..24 {
            for x in 0..24 {
                let at = (height / 2 + y) * width + width / 2 + x;
                pixels[at] = block(x);
                inside.push(at);
            }
        }
        (pixels, inside)
    }

    /// Regression: a small part of an image that has an entry of its own
    /// and a colour or two beyond what is far. Its entry was the one
    /// fewest pixels had, so it was the one given up for those colours,
    /// and the rest of it went to the nearest entry that was left: a
    /// shadow came out as opaque blue, a block of red as pink.
    #[test]
    fn test_entry_of_a_small_part_is_not_given_up() {
        let shadow = |x: usize| RGBA8::new(0, 0, 0, (x * 6) as u8);
        let red = |x: usize| RGBA8::new(255, (x * 6) as u8, 0, 255);
        let blocks: [(&str, &dyn Fn(usize) -> RGBA8); 2] =
            [("shadow", &shadow), ("red", &red)];
        for (name, block) in blocks {
            let (original, inside) = gradient_with_block(1000, 700, block);
            let mut seen = original.clone();
            premultiply(&mut seen);
            for quality in [100, 90] {
                let mut pixels = original.clone();
                let (palette, entries) =
                    quantize(&mut pixels, 1000, 700, quality).unwrap();
                let mut result = painted(&palette, &entries);
                premultiply(&mut result);
                let worst = inside
                    .iter()
                    .map(|at| {
                        let (a, b) = (seen[*at], result[*at]);
                        distance(&[a.r, a.g, a.b, a.a], &[b.r, b.g, b.b, b.a])
                            .sqrt() as u32
                    })
                    .max();
                assert_eq!(
                    true,
                    worst < Some(90),
                    "{name} {quality} {worst:?}"
                );
            }
        }
    }

    /// No more entries are taken from a net than its share, the clear
    /// one is never among them, and what was given up goes elsewhere.
    #[test]
    fn test_entries_of_their_own_are_few() {
        // Colours that nothing is near, each a mark of thirty pixels and
        // well apart from the next, and a clear corner.
        let mut original = smooth(600, 400);
        let mut marks = Vec::new();
        for r in [0, 128, 255] {
            for b in [0, 128, 255] {
                marks.push(RGBA8::new(r, 255, b, 255));
            }
            marks.push(RGBA8::new(r, 0, 0, 255));
            marks.push(RGBA8::new(r, 128, 0, 255));
        }
        for (mark, color) in marks.iter().enumerate() {
            let at = 15_000 * mark + 700;
            original[at..at + 30].fill(*color);
        }
        original[..2_000].fill(RGBA8::new(9, 9, 9, 0));
        premultiply(&mut original);
        let sample = Sample::new(&original);
        for size in [255, 127, 31] {
            let palette = Palette::trained(&sample, size, 64.0 * 64.0);
            // one more than the net where none of its neurons is clear
            let colors = palette.colors.len();
            assert_eq!(true, colors == size || colors == size + 1);
            let pinned = palette.pinned.len();
            assert_eq!(true, pinned <= colors / PINNED_SHARE, "{size}");
            // a large net has an entry to spare for most of them
            assert_eq!(true, size < 255 || pinned >= 8, "{pinned}");
            assert_eq!(Some(0), palette.clear);
            assert_eq!(CLEAR, palette.colors[0]);
            let Search::Net(_, entries) = &palette.search else {
                panic!("a net is what was trained");
            };
            // the net no longer gives anything to an entry that is taken
            for entry in palette.pinned.values() {
                assert_eq!(false, entries.contains(entry));
                assert_eq!(true, *entry != 0);
            }
            // and a colour that has an entry is given it
            for (key, entry) in palette.pinned.iter() {
                let color = palette.colors[usize::from(*entry)];
                assert_eq!(*key, u32::from_le_bytes(color) & palette.mask);
                assert_eq!(*entry, palette.entry_of(&color));
            }
        }

        // Noise: thousands of colours are far from every neuron, each of
        // a pixel or two, and every entry has pixels that would lose more
        // than those gain. Next to nothing is taken.
        let sample = Sample::new(&Noise(29).pixels(60_000, true));
        let palette = Palette::trained(&sample, 256, 1.0);
        assert_eq!(true, palette.pinned.len() < 8, "{}", palette.pinned.len());
    }

    /// A card on a clear ground, with a shadow that fades into it.
    fn card(width: usize, height: usize) -> Vec<RGBA8> {
        (0..width * height)
            .map(|at| {
                let (x, y) = ((at % width) as i64, (at / width) as i64);
                let (w, h) = (width as i64, height as i64);
                let outside = (w / 4 - x).max(x - w * 3 / 4).max(0)
                    + (h / 4 - y).max(y - h * 3 / 4).max(0);
                match outside {
                    // the card is not of one colour: there are more of
                    // them than a palette holds
                    0 => RGBA8::new(240, (x % 200) as u8, (y % 200) as u8, 255),
                    // a clear pixel has a colour of its own in the file
                    30.. => RGBA8::new(255, 255, 255, 0),
                    _ => RGBA8::new(10, 10, 20, (120 - outside * 4) as u8),
                }
            })
            .collect()
    }

    /// A pixel that is clear comes out clear, whatever is next to it. A
    /// palette that has no entry for it, or one that is nearly clear,
    /// puts a veil over everything that is behind the image.
    #[test]
    fn test_what_is_not_seen_stays_unseen() {
        // nothing to see at all
        let mut pixels = vec![RGBA8::new(9, 200, 30, 0); 70_000];
        let (palette, entries) = quantize(&mut pixels, 350, 200, 90).unwrap();
        assert_eq!(vec![RGBA8::new(0, 0, 0, 0)], palette);
        assert_eq!(true, entries.iter().all(|entry| *entry == 0));

        let mut noise = Noise(5);
        // every other pixel of noise
        let mut holes = noise.pixels(90_000, true);
        for pixel in holes.iter_mut().step_by(2) {
            pixel.a = 0;
        }
        // noise that fades into a clear edge three pixels wide
        let mut faded = noise.pixels(300 * 220, true);
        for (at, pixel) in faded.iter_mut().enumerate() {
            let (x, y) = (at % 300, at / 300);
            let edge = x.min(299 - x).min(y).min(219 - y);
            pixel.a = (edge.saturating_sub(2) * 8).min(255) as u8;
        }
        // a glow that fades from the middle
        let glow: Vec<RGBA8> = (0..256 * 256)
            .map(|at| {
                let (x, y) =
                    ((at % 256) as f64 - 128.0, (at / 256) as f64 - 128.0);
                let alpha = (255.0 - (x * x + y * y).sqrt() * 2.2).max(0.0);
                RGBA8::new(255, (at % 256) as u8, (at / 256) as u8, alpha as u8)
            })
            .collect();
        let images = [
            ("holes", holes, 300),
            ("faded", faded, 300),
            ("glow", glow, 256),
            ("card", card(400, 300), 400),
        ];
        for (name, original, width) in images.iter() {
            let clear = original.iter().filter(|pixel| pixel.a == 0).count();
            assert_eq!(true, clear > 0, "{name}");
            // each of them is one a net is trained for
            let mut seen = original.clone();
            premultiply(&mut seen);
            assert_eq!(false, Sample::new(&seen).fits, "{name}");
            for quality in [100, 90, 1] {
                let mut pixels = original.clone();
                let height = original.len() / width;
                let (palette, entries) =
                    quantize(&mut pixels, *width, height, quality).unwrap();
                assert_eq!(true, palette.len() <= 256, "{name} {quality}");
                let veiled = original
                    .iter()
                    .zip(painted(&palette, &entries))
                    .filter(|(pixel, to)| {
                        pixel.a == 0 && *to != RGBA8::new(0, 0, 0, 0)
                    })
                    .count();
                assert_eq!(0, veiled, "{name} {quality}");
            }
        }
    }

    /// Colours that fit into a palette as they are stay as they are, with
    /// a clear one among them too, and the entry for what is clear never
    /// makes a palette larger than it may be.
    #[test]
    fn test_clear_entry_has_its_place() {
        let mut noise = Noise(9);
        for visible in [254, 255, 256, 257] {
            let mut colors = noise.pixels(visible, true);
            colors.sort_unstable_by_key(|color| (color.r, color.g, color.b));
            colors.dedup();
            assert_eq!(visible, colors.len());
            let mut original: Vec<RGBA8> = (0..80_000)
                .map(|at| colors[at * 7 % colors.len()])
                .collect();
            original[..500].fill(RGBA8::new(1, 2, 3, 0));
            let mut pixels = original.clone();
            let (palette, entries) =
                quantize(&mut pixels, 400, 200, 100).unwrap();
            // 255 of them and the clear one are a palette; with more
            // there is a net, which has a neuron for what is clear
            let expected = if visible <= 255 { visible + 1 } else { 255 };
            assert_eq!(expected, palette.len(), "{visible}");
            let result = painted(&palette, &entries);
            assert_eq!(vec![RGBA8::new(0, 0, 0, 0); 500], result[..500]);
            // one colour too many is the first that is not exact
            let kept = original[500..] == result[500..];
            assert_eq!(visible <= 255, kept, "{visible}");
        }
    }

    #[test]
    fn test_same_image_same_result() {
        let original = Noise(21).pixels(150_000, false);
        let run = || {
            let mut pixels = original.clone();
            quantize(&mut pixels, 500, 300, 90).unwrap()
        };
        let first = run();
        assert_eq!(true, first == run());
        assert_eq!(256, first.0.len());
    }

    /// Regression: an image one pixel wide, or one pixel high, or of one
    /// pixel. The error of a pixel has nowhere to go at such an edge, and
    /// `image::imageops::dither` reaches past it.
    #[test]
    fn test_narrow_images() {
        for (width, height) in [(1, 5_000), (5_000, 1), (2, 2_500), (1, 1)] {
            for opaque in [true, false] {
                let original = Noise(41).pixels(width * height, opaque);
                let mut pixels = original.clone();
                let (palette, entries) =
                    quantize(&mut pixels, width, height, 90).unwrap();
                assert_eq!(width * height, entries.len());
                assert_eq!(true, palette.len() <= 256);
                assert_eq!(
                    true,
                    entries.iter().all(|e| usize::from(*e) < palette.len())
                );
            }
        }
    }

    /// The error of a pixel goes to the ones after it and below it, three
    /// quarters of it, in the shares 7, 3, 5 and 1 of 16.
    #[test]
    fn test_error_is_carried_on() {
        let mut carried = Carried::new(4);
        let pixel = [100, 100, 100, 255];
        // nothing has come to the first pixel
        assert_eq!(pixel, carried.wanted(1, pixel));
        // it wanted 164 and 36 where it got 100: 64 too little, 64 too much
        carried.spread(1, false, [164, 36, 100, 255], pixel);
        assert_eq!([121, 79, 100, 255], carried.wanted(2, pixel));
        assert_eq!(pixel, carried.wanted(0, pixel));
        carried.next_row();
        assert_eq!([109, 91, 100, 255], carried.wanted(0, pixel));
        assert_eq!([115, 85, 100, 255], carried.wanted(1, pixel));
        assert_eq!([103, 97, 100, 255], carried.wanted(2, pixel));
        assert_eq!(pixel, carried.wanted(3, pixel));

        // From right to left the shares are the other way round, and at
        // an edge what would go beyond it is not there.
        let mut carried = Carried::new(4);
        carried.spread(0, true, [164, 36, 100, 255], pixel);
        assert_eq!(pixel, carried.wanted(1, pixel));
        carried.next_row();
        assert_eq!([115, 85, 100, 255], carried.wanted(0, pixel));
        assert_eq!([109, 91, 100, 255], carried.wanted(1, pixel));
        assert_eq!(pixel, carried.wanted(2, pixel));

        // the last pixel of a row has no one after it
        let mut carried = Carried::new(4);
        carried.spread(3, false, [164, 36, 100, 255], pixel);
        carried.next_row();
        assert_eq!([115, 85, 100, 255], carried.wanted(3, pixel));
        assert_eq!([109, 91, 100, 255], carried.wanted(2, pixel));

        // No more than `MAX_CARRIED` comes to a pixel, however far off
        // the one before it was, and a colour stays within what a channel
        // holds.
        let mut carried = Carried::new(4);
        carried.spread(1, false, [255, 0, 100, 255], [0, 255, 100, 255]);
        assert_eq!([124, 76, 100, 255], carried.wanted(2, pixel));
        assert_eq!([255, 0, 100, 255], carried.wanted(2, [250, 5, 100, 255]));
    }

    #[test]
    fn test_size_that_is_not_the_pixels_is_refused() {
        let mut pixels = vec![RGBA8::new(1, 2, 3, 255); 12];
        assert_eq!(true, quantize(&mut pixels, 4, 3, 90).is_some());
        assert_eq!(true, quantize(&mut pixels, 4, 4, 90).is_none());
        assert_eq!(true, quantize(&mut pixels, usize::MAX, 2, 90).is_none());
        assert_eq!(true, quantize(&mut [], 0, 0, 90).is_none());
    }
}
